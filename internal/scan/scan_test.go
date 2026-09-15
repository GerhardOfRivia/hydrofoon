package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"hydrofoon/internal/model"
)

type message struct {
	reply   Reply
	barrier chan struct{}
	err     error
}
type fakeIO struct {
	input     chan message
	done      chan struct{}
	once      sync.Once
	requests  []netip.Addr
	onRequest func(netip.Addr, int) error
	started   chan struct{}
	startOnce sync.Once
}

func newIO() *fakeIO {
	return &fakeIO{input: make(chan message, 64), done: make(chan struct{}), started: make(chan struct{})}
}
func (f *fakeIO) Request(ip netip.Addr) error {
	f.requests = append(f.requests, ip)
	if f.onRequest != nil {
		return f.onRequest(ip, len(f.requests))
	}
	return nil
}
func (f *fakeIO) Read() (Reply, error) {
	f.startOnce.Do(func() { close(f.started) })
	for {
		select {
		case <-f.done:
			return Reply{}, net.ErrClosed
		case m := <-f.input:
			if m.barrier != nil {
				close(m.barrier)
				continue
			}
			return m.reply, m.err
		}
	}
}
func (f *fakeIO) Close() error { f.once.Do(func() { close(f.done) }); return nil }
func (f *fakeIO) drain(ctx context.Context) error {
	b := make(chan struct{})
	select {
	case f.input <- message{barrier: b}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-b:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	sleep func(context.Context, time.Duration) error
	waits []time.Duration
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.sleep != nil {
		if err := c.sleep(ctx, d); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.waits = append(c.waits, d)
	c.mu.Unlock()
	return nil
}
func setup(f *fakeIO) *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), sleep: func(ctx context.Context, _ time.Duration) error { return f.drain(ctx) }}
}
func reply(ip, mac string) message {
	m, _ := net.ParseMAC(mac)
	return message{reply: Reply{IP: netip.MustParseAddr(ip), MAC: m}}
}
func options() Options { return Options{Rate: 100, Retries: 1, Wait: time.Second, MaxTargets: 4096} }

var scope = model.Scope{Interface: "fake0", CIDR: "10.50.0.0/30"}

func TestRetriesDeduplicationAndConflicts(t *testing.T) {
	f := newIO()
	c := setup(f)
	f.onRequest = func(ip netip.Addr, n int) error {
		if n == 1 {
			for _, m := range []message{reply("10.50.0.1", "02:11:22:33:44:01"), reply("10.50.0.1", "02:11:22:33:44:01"), reply("10.50.0.1", "02:11:22:33:44:02"), reply("10.50.1.1", "02:11:22:33:44:03"), reply("10.50.0.2", "ff:ff:ff:ff:ff:ff")} {
				f.input <- m
			}
		}
		if n == 3 {
			f.input <- reply(ip.String(), "02:11:22:33:44:01")
		}
		return nil
	}
	r, err := Run(context.Background(), f, scope, netip.MustParsePrefix(scope.CIDR), options(), c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Requests != 3 || len(f.requests) != 3 || f.requests[2].String() != "10.50.0.2" {
		t.Fatalf("requests: %+v", f.requests)
	}
	if len(r.Observations) != 3 {
		t.Fatalf("observations: %+v", r.Observations)
	}
	if !r.Observations[0].Conflict || !r.Observations[1].Conflict || r.Observations[2].Conflict {
		t.Fatal(r.Observations)
	}
	if r.Observations[0].MAC != r.Observations[2].MAC {
		t.Fatal("lost multiple IPs per MAC")
	}
	select {
	case <-f.done:
	default:
		t.Fatal("not closed")
	}
	// Three requests have two pacing waits; both rounds have a response window.
	if len(c.waits) != 4 || c.waits[0] != 10*time.Millisecond || c.waits[1] != time.Second || c.waits[3] != time.Second {
		t.Fatalf("pacing: %v", c.waits)
	}
}

func TestUnansweredRetriesAndLimits(t *testing.T) {
	f := newIO()
	o := options()
	o.Retries = 2
	r, err := Run(context.Background(), f, scope, netip.MustParsePrefix("10.50.0.1/32"), o, setup(f))
	if err != nil || r.Requests != 3 {
		t.Fatal(r, err)
	}
	f = newIO()
	o.MaxTargets = 1
	if _, err := Run(context.Background(), f, scope, netip.MustParsePrefix(scope.CIDR), o, setup(f)); err == nil || len(f.requests) != 0 {
		t.Fatal("limit did not prevent sending")
	}
}

func TestCancellationUnblocksReadAndWrite(t *testing.T) {
	for _, blockedWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "write"}[blockedWrite], func(t *testing.T) {
			f := newIO()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if blockedWrite {
				f.onRequest = func(netip.Addr, int) error { cancel(); <-f.done; return net.ErrClosed }
			}
			if !blockedWrite {
				f.onRequest = func(netip.Addr, int) error { cancel(); return nil }
			}
			done := make(chan error, 1)
			go func() {
				_, err := Run(ctx, f, scope, netip.MustParsePrefix(scope.CIDR), options(), RealClock{})
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation leaked goroutines")
			}
		})
	}
}

func TestIOErrorsAndObservationBound(t *testing.T) {
	for _, kind := range []string{"read", "write", "flood"} {
		t.Run(kind, func(t *testing.T) {
			f := newIO()
			f.onRequest = func(netip.Addr, int) error {
				if kind == "write" {
					return errors.New("write broken")
				}
				if kind == "read" {
					f.input <- message{err: errors.New("read broken")}
				}
				if kind == "flood" {
					for n := byte(1); n <= 9; n++ {
						f.input <- message{reply: Reply{IP: netip.MustParseAddr("10.50.0.1"), MAC: net.HardwareAddr{2, 0, 0, 0, 0, n}}}
					}
				}
				return nil
			}
			if _, err := Run(context.Background(), f, scope, netip.MustParsePrefix("10.50.0.1/32"), options(), setup(f)); err == nil {
				t.Fatal("expected failure")
			}
		})
	}
}
