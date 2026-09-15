// Package scan coordinates a paced sender and one concurrent packet receiver.
package scan

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"hydrofoon/internal/model"
	"hydrofoon/internal/network"
)

type Reply struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

// PacketIO has exactly one reader and one writer. Close must promptly unblock
// both Read and Request, and may run concurrently with either method.
// Run takes ownership and closes it on every exit, including invalid options.
type PacketIO interface {
	Request(netip.Addr) error
	Read() (Reply, error)
	Close() error
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }
func (RealClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type Options struct {
	Rate       float64
	Retries    int
	Wait       time.Duration
	MaxTargets int
}

func (o Options) Validate() error {
	if math.IsNaN(o.Rate) || math.IsInf(o.Rate, 0) || o.Rate < 0.1 || o.Rate > 100000 {
		return fmt.Errorf("--rate must be between 0.1 and 100000 packets/second")
	}
	if o.Retries < 0 || o.Retries > 10 {
		return fmt.Errorf("--retries must be between 0 and 10")
	}
	if o.Wait <= 0 || o.Wait > time.Minute {
		return fmt.Errorf("--wait must be greater than zero and at most 1m")
	}
	if o.MaxTargets < 1 || o.MaxTargets > network.HardMaxTargets {
		return fmt.Errorf("--max-targets must be between 1 and %d", network.HardMaxTargets)
	}
	return nil
}

var errComplete = errors.New("scan complete")

func Run(parent context.Context, pio PacketIO, scope model.Scope, prefix netip.Prefix, o Options, clock Clock) (model.Scan, error) {
	if err := o.Validate(); err != nil {
		pio.Close()
		return model.Scan{}, err
	}
	targets, err := network.Targets(prefix, o.MaxTargets)
	if err != nil {
		pio.Close()
		return model.Scan{}, err
	}
	if clock == nil {
		clock = RealClock{}
	}
	ctx, cancel := context.WithCancelCause(parent)
	result := model.Scan{SchemaVersion: model.SchemaVersion, Scope: scope, StartedAt: model.UTC(clock.Now()), Targets: len(targets), Observations: []model.Observation{}}
	var mu sync.Mutex
	observed := make(map[string]model.Observation)
	answered := make(map[netip.Addr]bool)
	// A hostile or broken peer must not grow a scan without bound. Exhaustion
	// fails the entire scan so watch cannot mistake truncation for absence.
	maxObservations := min(len(targets)*8, network.HardMaxTargets)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-ctx.Done(); _ = pio.Close() }()
	ready := make(chan struct{})
	go func() {
		defer wg.Done()
		close(ready)
		for ctx.Err() == nil {
			r, err := pio.Read()
			if err != nil {
				if ctx.Err() == nil {
					cancel(fmt.Errorf("read ARP replies: %w", err))
				}
				return
			}
			if !r.IP.Is4() || !prefix.Contains(r.IP) || !validMAC(r.MAC) || r.IP.IsUnspecified() || r.IP.IsMulticast() {
				continue
			}
			mac := r.MAC.String()
			key := r.IP.String() + "/" + mac
			mu.Lock()
			if _, ok := observed[key]; !ok && len(observed) >= maxObservations {
				mu.Unlock()
				cancel(fmt.Errorf("scan exceeded %d distinct IP/MAC observations; possible ARP flood", maxObservations))
				return
			}
			observed[key] = model.Observation{IP: r.IP.String(), MAC: mac, ObservedAt: model.UTC(clock.Now())}
			answered[r.IP] = true
			mu.Unlock()
		}
	}()
	<-ready
	// The next send is scheduled relative to the actual preceding request,
	// so scheduler delays never cause catch-up bursts.
	gap := time.Duration(float64(time.Second) / o.Rate)
	var lastSend time.Time
	send := func() error {
		for round := 0; round <= o.Retries; round++ {
			for _, ip := range targets {
				if err := ctx.Err(); err != nil {
					return err
				}
				mu.Lock()
				skip := round > 0 && answered[ip]
				mu.Unlock()
				if skip {
					continue
				}
				if !lastSend.IsZero() {
					if err := clock.Sleep(ctx, max(time.Duration(0), gap-clock.Now().Sub(lastSend))); err != nil {
						return err
					}
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				// Recheck after pacing: a reply may have arrived while waiting.
				mu.Lock()
				skip = round > 0 && answered[ip]
				mu.Unlock()
				if skip {
					continue
				}
				if err := pio.Request(ip); err != nil {
					return fmt.Errorf("request ARP for %s: %w", ip, err)
				}
				result.Requests++
				lastSend = clock.Now()
			}
			// Also wait between rounds, giving even a /32 time to answer before
			// deciding which addresses need a retry.
			if err := clock.Sleep(ctx, o.Wait); err != nil {
				return err
			}
		}
		return nil
	}
	err = send()
	if err != nil {
		cancel(err)
	} else {
		cancel(errComplete)
	}
	wg.Wait()
	if cause := context.Cause(ctx); cause != errComplete {
		return model.Scan{}, cause
	}
	counts := make(map[string]int)
	for _, ob := range observed {
		counts[ob.IP]++
	}
	for _, ob := range observed {
		ob.Conflict = counts[ob.IP] > 1
		result.Observations = append(result.Observations, ob)
	}
	model.SortObservations(result.Observations)
	result.FinishedAt = model.UTC(clock.Now())
	return result, nil
}

func validMAC(m net.HardwareAddr) bool {
	if len(m) != 6 || m[0]&1 != 0 {
		return false
	}
	for _, b := range m {
		if b != 0 {
			return true
		}
	}
	return false
}
