# hydrofoon

`hydrofoon` is a Linux-only CLI for finding compute platforms on a lab network
using IPv4 ARP. Enroll each asset's NIC MAC addresses to attach asset IDs and
names to observations, or scan without an inventory to discover unknown devices.
It only discovers and tracks devices. It does not deploy software, run remote
commands, or update platforms.

## Build and check

Requires Linux and Go 1.23 or newer. The race detector also needs a supported
architecture and a C compiler. No root privileges or live network are required
for the automated tests.

### Local Go environment

If you keep a Go toolchain in `.go/toolchain` (with an executable
`.go/toolchain/bin/go`), activate it in your current Bash shell:

```bash
source ./activate
```

Activation checks the local toolchain, creates the Go workspace and cache
directories under `.go`, and adds the toolchain and `.go/gopath/bin` to `PATH`.
Your prompt gains a `(hydrofoon)` prefix. You can source the script by its full
path from any directory; sourcing it again does not duplicate the prompt or
`PATH` entries. A missing directory or toolchain reports an error before changing
your shell environment.

Run `hydrofoon_deactivate` to restore your previous prompt and environment.
If you activate other environments too, deactivate them in reverse order.
`make activate` prints the sourcing command, since Make cannot change its parent
shell's environment.

### Commands

```sh
make build                       # bin/hydrofoon, static Go binary, CGO disabled
make build VERSION=0.1.0          # embed a release version
make check                       # formatting, vet, tests, race detector
./bin/hydrofoon version
./bin/hydrofoon --help
```

Equivalent commands:

```sh
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o bin/hydrofoon ./cmd/hydrofoon
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
```

Builds disable automatic VCS stamping so source archives and workspaces without
Git metadata also build; use `VERSION` for the explicit version stamp.

The executable uses Go libraries directly; it never invokes `arp-scan`, `nmap`,
`ip`, `ping`, a shell, or another executable. There is no libpcap, external
database, HTTP server, or web framework dependency. The module pins
[`github.com/mdlayher/arp`](https://github.com/mdlayher/arp) at
`v0.0.0-20260528070854-93566ba168e9` (requires Go 1.23), plus its Ethernet/raw
socket dependencies. YAML uses `gopkg.in/yaml.v3` v3.0.1; other application code
uses the standard library. `go.sum` records dependency checksums.

## Run

Only scan networks you are explicitly authorized to scan. Choose an Ethernet
interface, bridge, or VLAN interface connected to the lab's Layer-2 network.

```sh
sudo ./bin/hydrofoon scan --interface eno1 --cidr 10.50.0.0/24

sudo ./bin/hydrofoon scan --interface eno1 --cidr 10.50.0.0/24 \
  --inventory devices.json

sudo ./bin/hydrofoon scan --interface eno1 --cidr 10.50.0.0/24 \
  --mac 02:11:22:33:44:01 --json

sudo ./bin/hydrofoon watch --interface eno1 --cidr 10.50.0.0/24 \
  --inventory devices.json --interval 30s --state hydrofoon-state.json

sudo ./bin/hydrofoon watch --interface eno1 --cidr 10.50.0.0/24 \
  --inventory devices.yaml --state hydrofoon-state.json --json
```

`--interface` is mandatory. If `--cidr` is omitted, the selected interface must
have exactly one distinct usable IPv4 subnet. Multiple addresses in that same
subnet are fine; multiple different subnets require an explicit `--cidr`.
An IPv4 address must be configured even when a CIDR is supplied. The interface
must be up and have a six-byte Ethernet MAC address.

CIDRs are canonicalized, so `10.50.0.9/24` selects `10.50.0.0/24`. Ordinary
subnets exclude network/broadcast addresses from probing; `/31` probes both
addresses and `/32` probes its single address. All requests stay within the
selected subnet. The local host's address is included in enumeration, but a
host generally does not answer its own raw ARP request.

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--interface` | required | Interface on which to bind the raw socket |
| `--cidr` | derived if unambiguous | IPv4 range to probe |
| `--inventory` | none | JSON enrollment file, or `.yaml` / `.yml` |
| `--mac` | none | Full MAC output filter, applied **after discovery** |
| `--json` | false | One scan JSON document, or watch NDJSON |
| `--rate` | `100` | Requests/second, from 0.1 to 100,000 |
| `--retries` | `1` | Extra attempts for unanswered targets, from 0 to 10 |
| `--wait` | `2s` | Response window between rounds and after the final round; greater than 0, at most 1 minute |
| `--max-targets` | `4096` | Target limit; explicitly raise to allow larger ranges, up to 1,048,576 |
| `--interval` | `30s` | Watch only: delay **after completion** of each scan, greater than 0, at most 24 hours |
| `--stale-after` | `3` | Watch only: missed successful scans before an interface is stale |
| `--state` | none | Watch only: persisted JSON state; omitted means in-memory tracking |

Use `scan --help` or `watch --help` for built-in help. Standard Go flag syntax is
supported (`--rate 50` and `--rate=50`); positional arguments are rejected.
`--mac` never reduces probe traffic or state tracking. A filtered observation
still carries its conflict flag even when the other claimant is hidden.
Watch filters entity/conflict events by their participant MACs; scan errors
always appear.

### Privileges

Raw ARP sockets require root or `CAP_NET_RAW`. Running with `sudo` as above is
the simplest option. To run as your own user, install a **trusted** binary in a
root-owned location, then grant only the raw-socket capability:

```sh
sudo install -o root -g root -m 0755 bin/hydrofoon /usr/local/bin/hydrofoon
sudo setcap cap_net_raw=ep /usr/local/bin/hydrofoon
getcap /usr/local/bin/hydrofoon
hydrofoon scan --interface eno1 --cidr 10.50.0.0/24
```

These are manual administrative setup commands, not subprocesses launched by
the application. `setcap`/`getcap` come from your distribution's capability
utilities package. The capability permits raw packet access; grant it only to
a binary you trust and keep the binary protected from untrusted replacement.
Your user also needs write access to the watch state directory. Remove the
grant with:

```sh
sudo setcap -r /usr/local/bin/hydrofoon
```

Capabilities may need to be reapplied after replacing/rebuilding/reinstalling
the executable. Containers and restricted environments may additionally limit
raw sockets or network namespace access.

## Enrollment

See json or yaml for complete, equivalent examples:

```json
{
  "devices": [
    {
      "asset_id": "MCP-001",
      "name": "Mobile compute platform 001",
      "macs": ["02:11:22:33:44:01", "02:11:22:33:44:02"]
    },
    {
      "asset_id": "MCP-002",
      "name": "Mobile compute platform 002",
      "macs": ["02:11:22:33:44:03"]
    }
  ]
}
```

```yaml
devices:
  - asset_id: MCP-001
    name: Mobile compute platform 001
    macs:
      - "02:11:22:33:44:01"
      - "02:11:22:33:44:02"
  - asset_id: MCP-002
    name: Mobile compute platform 002
    macs:
      - "02:11:22:33:44:03"
```

Asset IDs must be nonempty and unique, with no surrounding whitespace. Each
asset must have at least one MAC. MACs must parse as six-byte addresses; they
are normalized to lowercase colon-separated notation. Duplicate MACs, including
duplicates within an asset, are rejected. Matching always uses all six bytes,
never a manufacturer prefix. Unknown fields and multiple documents are rejected.
Files are limited to 8 MiB. Use `{"devices": []}` for an empty inventory.

An asset and its NICs are separate identities: multiple MACs can belong to one
asset, and one MAC can be observed at multiple IPs. Unenrolled observations show
as `unknown` in the table. The inventory is read once at startup and is never
written; restart a watcher to reload enrollment changes. Stored observations
are reassociated with the current inventory on the next successful scan.

## Scan behavior

Each scan binds one raw socket to the selected interface. A dedicated receive
loop starts before the paced sender. The sender uses `arp.Client.Request`;
the receiver uses `Read`. The implementation does not use `Resolve` and does
not create a goroutine per target.

After each request round, the receiver remains active for `--wait`. Only IPs
without a valid reply are retried. A final response window also runs when all
targets answered, allowing late and conflicting replies to be recorded. Total
runtime includes pacing and response windows. Requests never burst to catch up
after a scheduling delay.

Only Ethernet/IPv4 ARP replies with matching Ethernet/ARP sender MACs, a unicast
six-byte nonzero MAC, and a sender IP in the selected subnet are accepted.
Valid unsolicited replies in that subnet may also be observed. Deduplication
uses the **IP/MAC pair**; the timestamp is the last accepted reply for that pair
within the scan. Conflicting IP claims remain separate observations.

SIGINT/SIGTERM cancel sending and waits, close the packet socket to unblock I/O,
and join scan goroutines. Socket errors fail the scan as a whole; partial results
are never treated as successful discovery. A scan fails if distinct observations
exceed the smaller of eight times its target count and 1,048,576, avoiding
unbounded memory use during an ARP flood.

## Watch state and event semantics

Watch scans immediately, then waits `--interval` after each attempt finishes.
Scans never overlap. A failed or cancelled scan leaves all observation history,
miss counters, statuses, and conflicts unchanged. Ordinary packet scan failures
emit `scan_error` and retry at the next interval; cancellation exits promptly.
State processing/persistence errors emit `scan_error` and stop the watcher.

Each observed NIC stores `first_seen`, `last_seen`, consecutive `missed_scans`,
`status` (`seen` or `stale`), its latest observed IP set, and historical IP
mappings with first/last observation times. Miss counters reset only when that
MAC is observed in a successful scan. Below the threshold, status remains `seen`;
this means recently observed, not definitively online. A stale NIC retains its
last observed IPs and history. Unobserved inventory NICs do not create records.

Device transitions aggregate **all previously observed NICs enrolled to the
same asset**. An unknown MAC is its own device. A known asset becomes stale
only when all its recorded NICs are stale. Seeing a new NIC for an existing
seen asset does not produce another `device_seen` event.

| Event | Meaning |
| --- | --- |
| `device_seen` | First observation of an asset, or of an unknown MAC |
| `device_returned` | A previously stale asset/unknown device becomes seen |
| `ip_changed` | A NIC's complete observed IP set differs from the last successful scan in which that NIC appeared; includes old/new sets |
| `device_stale` | All recorded NICs of an asset, or an unknown MAC, reach stale status |
| `ip_conflict` | At least two MACs claim one IP in a successful scan; emitted when the claimant set is new or changes |
| `scan_error` | One failed scan attempt, cancellation during a scan, or a fatal state-processing error; includes error text |

No repeated unchanged device/IP/conflict transitions are emitted. A successful
scan without a conflict clears that conflict's active set; a later recurrence
emits a new event. There is no separate conflict-resolved event. Failed scans
do not clear conflicts. Changes in the enrolled asset for a previously recorded
MAC are reassociations, not new device events. Entity events include all
recorded participant `macs`; `ip_changed` identifies a single `mac`.

### Persistence

`--state` writes a schema-versioned JSON file, scoped to the **interface name
and canonical subnet**. Reusing a state file with a different scope fails;
use different files for different networks. Inventory and state/lock paths
must be separate. Watch creates a `.lock` sidecar with a cooperative exclusive
lock held for its entire lifetime. The sidecar is retained after exit, but the
kernel releases its lock. Only one watcher may use a given state path.

Successful updates use a private temporary file in the same directory, `fsync`,
atomic rename, and directory `fsync`. State files have mode `0600`. The parent
directory must already exist. Symlink/nonregular state files, invalid schemas,
inconsistent records, and malformed JSON stop startup **without replacing the
existing state**. Inspect or archive a damaged file manually before restarting;
do not edit state while watch is running.

State is limited to 65,536 NICs, 262,144 historical IP/MAC mappings, and a 64 MiB
JSON file. Reaching a limit stops the watcher without discarding evidence;
archive the state and choose a new file to start a fresh tracking period.
Clock times must not move backwards past persisted `updated_at`.

State is committed before events are written to stdout. Event delivery is not
transactional with file persistence: a crash or broken output pipe between those
steps can lose events. State records are authoritative observations; stdout is
not a durable event journal.

## Output schema (version 1)

All timestamps are UTC RFC3339 with whole-second precision. IP lists sort
numerically; observations sort by IP, then MAC. Events use deterministic entity,
MAC, and IP ordering within each successful scan. Empty observation results are
`[]`. Diagnostics go to stderr. Normal scan stdout is a table with asset ID,
name, IP, MAC, observation time, and a conflict marker.

`scan --json` writes exactly one document on success and none on failure:

```json
{
  "schema_version": 1,
  "scope": {"interface": "eno1", "cidr": "10.50.0.0/24"},
  "started_at": "2026-09-15T12:00:00Z",
  "finished_at": "2026-09-15T12:00:06Z",
  "targets": 254,
  "requests": 507,
  "observations": [
    {
      "asset_id": "MCP-001",
      "name": "Mobile compute platform 001",
      "ip": "10.50.0.42",
      "mac": "02:11:22:33:44:01",
      "observed_at": "2026-09-15T12:00:01Z",
      "conflict": false
    }
  ]
}
```

`targets` is the full enumerated address count and `requests` counts requests
actually sent, including retries; neither is reduced by `--mac`. `asset_id` and
`name` are omitted when unknown/empty. `conflict` always appears.

`watch --json` emits one compact JSON event per line (NDJSON), for example:

```jsonl
{"schema_version":1,"type":"device_seen","time":"2026-09-15T12:00:06Z","scope":{"interface":"eno1","cidr":"10.50.0.0/24"},"asset_id":"MCP-001","name":"Mobile compute platform 001","macs":["02:11:22:33:44:01"]}
{"schema_version":1,"type":"ip_changed","time":"2026-09-15T12:01:18Z","scope":{"interface":"eno1","cidr":"10.50.0.0/24"},"asset_id":"MCP-001","mac":"02:11:22:33:44:01","ips":["10.50.0.43"],"previous_ips":["10.50.0.42"]}
```

Every event has `schema_version`, `type`, `time`, and `scope`. Optional fields
are `asset_id`, `name`, `mac`, `macs`, `ip`, `ips`, `previous_ips`, and `error`,
according to the semantics above. `ip_conflict` has `ip` and sorted `macs`;
`scan_error` has `error`. Device event times indicate the successful scan's
completion, while interface timestamps indicate received evidence.

Exit codes: `0` for successful scan/help/version, `1` for input or fatal errors,
and `130` for context cancellation via SIGINT/SIGTERM. Recoverable watch scan
errors keep the process running and appear in the event stream and stderr.

## Limitations

- ARP is **IPv4 only** and requires access to the **same Layer-2 network/VLAN**;
  it does not discover through routers. Select a configured VLAN interface when
  appropriate; hydrofoon does not create VLANs.
- A platform configured outside the scanned range may not be discovered.
  Silent hosts, sleeping NICs, filtering, congestion, or packet loss may also
  suppress replies. Lack of a reply is **not proof of disconnection**.
- A MAC match is **not authenticated device identity**. MACs can be spoofed,
  reused, or randomized, and proxy ARP can make many IPs appear at one MAC.
  Neither enrollment nor discovery must authorize software deployment.
- The pinned ARP library selects the interface's first IPv4 address as the ARP
  source address. An explicit scan CIDR does not change that source. On interfaces
  with several IPv4 subnets, some peers may not answer an off-subnet source;
  use an appropriately configured lab interface.
- Interface name and subnet are the persistence boundary. Moving an interface
  to a different physical network with the same name/range is not automatically
  detected; start a separate state file.
- History is bounded and retained until you archive/reset the state. There is
  no automatic retention policy, event replay service, or multi-writer support.

## Source layout and tests

- `cmd/hydrofoon`: Linux entry point and signal handling.
- `internal/packet`: Linux packet adapter and ARP validation.
- `internal/scan`: paced requests, concurrent replies, retries, cancellation.
- `internal/network`: interface selection, IPv4 enumeration, target bounds.
- `internal/inventory`: read-only enrollment and full-MAC matching.
- `internal/state`: interface/asset transitions, conflicts, atomic persistence.
- `internal/model`: shared versioned schemas and deterministic ordering.
- `internal/cli`: flags, output, and nonoverlapping watch orchestration.

Tests use fake packet I/O and injected clocks. They cover subnet edges/limits,
inventory validation, matching/filtering, retries/pacing, deduplication, multiple
IPs per MAC, conflicts, I/O failures, bounded observations, blocked-read/write
cancellation, asset aggregation, stale/returned transitions, failed/cancelled
scans, persistence, scope mismatch, locks, and JSON output. Automated tests do
not claim privileged live-network validation.

## development

Install [Go](https://go.dev/dl/) at the version required by `go.mod` or newer.
For a repository-local toolchain, place Go at `.go/toolchain/bin/go` and run
`source activate` to select it and keep Go's caches under `.go`.

### isolated temporary Go toolchain

If Go is not installed, or you want to keep the toolchain and its caches out of
your home directory, you can download Go into a temporary directory. This
example uses Go 1.27.0 for Linux on AMD64; choose another published version or
supported Linux architecture from [go.dev/dl](https://go.dev/dl/) when needed.

```bash
export HYDROFOON_GO_VERSION=1.27.0
export HYDROFOON_GO_OS=linux
export HYDROFOON_GO_ARCH=amd64
export HYDROFOON_GO_DIR=$(pwd)/.go

mkdir -p "$HYDROFOON_GO_DIR/toolchain"
curl -fL \
  "https://go.dev/dl/go${HYDROFOON_GO_VERSION}.${HYDROFOON_GO_OS}-${HYDROFOON_GO_ARCH}.tar.gz" \
  -o "$HYDROFOON_GO_DIR/go.tar.gz"
tar -xzf "$HYDROFOON_GO_DIR/go.tar.gz" \
  -C "$HYDROFOON_GO_DIR/toolchain" \
  --strip-components=1

export PATH="$HYDROFOON_GO_DIR/toolchain/bin:$PATH"
export GOPATH="$HYDROFOON_GO_DIR/gopath"
export GOMODCACHE="$HYDROFOON_GO_DIR/modcache"
export GOCACHE="$HYDROFOON_GO_DIR/buildcache"

go version
go mod download
```

`PATH` selects the temporary Go binary, `GOPATH` isolates Go's workspace,
`GOMODCACHE` isolates downloaded modules, and `GOCACHE` isolates compiled build
artifacts. You do not need to set `GOROOT`; the Go binary discovers its own
toolchain directory. These exports affect only the current shell.

For Linux on ARM64, set `HYDROFOON_GO_ARCH=arm64`.

To remove the temporary toolchain and caches when you are finished:

```bash
if [ -n "${HYDROFOON_GO_DIR:-}" ] && [ -d "$HYDROFOON_GO_DIR" ]; then
  rm -rf -- "$HYDROFOON_GO_DIR"
fi
unset HYDROFOON_GO_DIR HYDROFOON_GO_VERSION HYDROFOON_GO_OS HYDROFOON_GO_ARCH
unset GOPATH GOMODCACHE GOCACHE
hash -r
```

### checks

```bash
go fmt ./...
go vet ./...
go test ./...
```

### build

```bash
make
./bin/hydrofoon version
```

![icon.png](icon.png)
