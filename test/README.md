# GnuGk test harness

End-to-end tests that run the real `gnugk` binary with real H.323 endpoints.

**Basic calls** (`test_calls.py`), the matrix of
- calls between public endpoints, with and without the RTP proxy, media opened with fastStart
  or with H.245
- calls with H.460.18/.19 NAT traversal (caller, callee or both behind NAT), media opened with
  H.245 (fastStart isn't tested with H.460.18/.19)
- each of those with four authentication setups (`SimplePasswordAuth`):
  - `noauth`: no authentication
  - `md5`: MD5 tokens, `required;RRQ,URQ,ARQ,BRQ,DRQ` (the messages H323Plus puts MD5 tokens into)
  - `h2351-setup`: H.235.1 (Procedure I) tokens, `required;RRQ,URQ,ARQ,BRQ,DRQ,Setup`
  - `h2351-all`: H.235.1 tokens, a bare `required` (all supported RAS and Q.931 messages, with
    the default `[H235] FullQ931Checking=0`)

A call passes when both endpoints registered, the call connected, RTP flowed in **both**
directions for the whole call (through the proxy or not, checked in the pcap), GnuGk wrote one
CDR with the right duration and cause, no call was left over and both endpoints could unregister.

**More areas**

| file | what |
|---|---|
| `test_call_handling.py` | unknown alias, callee refuses (busy / rejected), callee hangs up, caller hangs up while ringing, unregistered caller (`AcceptUnregisteredCalls`), endpoint killed mid-call, separate H.245 channel, `H245TunnelingTranslation`, E.164 numbers and several aliases, call duration limit, Q.931 cause translation, 5 parallel calls |
| `test_registration.py` | duplicate alias, keep-alive RRQs (no auth, MD5, H.235.1), registration expiry (with and without IRQ poll), additive registration |
| `test_registration_auth.py` | MD5 and H.235.1 registration: right / wrong / missing password, unknown user |
| `test_routing.py` | direct mode, routed without H.245 routing, explicit IP dialing, registered callee dialed by IP, permanent gateway, gateway prefixes, round robin, failover, `RewriteE164`, `GWRewriteE164`, `RewriteCLI`, virtual queue (status port routing) |
| `test_auth_modules.py` | `FileIPAuth`, `AliasAuth` / `[RasSrv::RRQAuth]` (sigip, also for E.164 numbers, sigaddr, allow / deny, `&` and `|`, alias order, default rule), `PrefixAuth` |
| `test_sql.py` | SQLite backed `SQLPasswordAuth`, `SQLAliasAuth`, `SQLAuth` (RegQuery, CallQuery on ARQ / Setup / SetupUnreg with its result columns, NbQuery), SQL routing policy |
| `test_capacity.py` | `[EP::...] Capacity`, `CapacityControl`, `TotalBandwidth`, `MaximumBandwidthPerCall`, BRQ |
| `test_admin.py` | config reload during a call, status port commands (`PrintCurrentCalls`, `DisconnectCall`, `UnregisterAlias`, `Statistics`, `PrintEndpointQoS`), status port login rules and event filters, `StatusAcct` / `SQLAcct` events, `RerouteCall` |
| `test_nat.py` | H.460.18 behind NATs that drop idle UDP mappings after 10 seconds, two H.460.18 endpoints behind the same NAT |
| `test_media.py` | RTCP through the RTP proxy and `EnableRTCPStats`, H.460.19 RTP multiplexing |
| `test_multi_gk.py` | neighbor gatekeepers (also with both proxying, and H.460.18 neighbor traversal), child gatekeeper registered with a parent |
| `test_soak.py` | 100 calls in a row, GnuGk's memory, file descriptors and threads must stay flat |
| `test_ipv6.py` | IPv6 calls, also IPv4 to IPv6 (skipped without kernel IPv6 support) |

## Requirements

- Linux, run as **root** (the tests create network namespaces and iptables NAT rules)
- `ip` (iproute2), `iptables`, `tcpdump` (optional, for pcaps), Python 3 with `pytest`
- a C++ toolchain and the usual PTLib build dependencies (bison, flex, OpenSSL headers)
- for the IPv6 tests a kernel with IPv6 support, they are skipped otherwise

## Build

```bash
test/build-deps.sh
```

This clones or updates the latest commit of the default branch (GitHub HEAD) of
[willamowius/ptlib](https://github.com/willamowius/ptlib) and
[willamowius/h323plus](https://github.com/willamowius/h323plus) into `~/gnugk-test-deps`
(or the directory given as argument / `$GKTEST_DEPS`), builds them (H323Plus with the
options from the GnuGk manual: `--enable-h235 --enable-h46017 --enable-h46026`; without H.235
GnuGk can't verify H.235.1 tokens), then builds GnuGk with `--enable-h46018 --enable-large-fdset`, `addpasswd` and
the test endpoint. Build logs go to `<deps>/logs/`.
Run it again after changing GnuGk code (it always rebuilds GnuGk from scratch).

For a quick rebuild of GnuGk only:

```bash
export PTLIBDIR=~/gnugk-test-deps/ptlib OPENH323DIR=~/gnugk-test-deps/h323plus
make optnoshared
```

(but do a clean build, `rm -rf obj_*_s` first, if you changed the configure options)

## Run

```bash
test/run.sh                          # everything, about 35 minutes
test/run.sh -k "h46018 and md5"      # a subset
test/run.sh -k h2351                 # all H.235.1 tests
test/run.sh -x -k plain-noauth       # stop at the first failure
test/run.sh --collect-only -q        # list all tests with what they check (works without root and without a build)
test/run.sh -v --describe -k md5     # run, with what each test checks below its result
test/run.sh --collect-only -q -k md5 # list the tests a -k expression selects
```

To test another GnuGk binary (eg. an older version, to see whether a failure is a regression):

```bash
GKTEST_GNUGK=/path/to/gnugk test/run.sh
```

Each test leaves its files in `test/results/<test name>/`:

| file | content |
|---|---|
| `gnugk.ini` | the generated GnuGk config |
| `gnugk.trace` | GnuGk trace (level 5) |
| `gk.pcap` | everything the gatekeeper host saw |
| `cdr.txt` | CDRs from FileAcct |
| `ep-<alias>.json` | what each endpoint saw (registration, call, RTP counters, end reason) |
| `ep-<alias>.trace` | H323Plus trace of each endpoint |
| `gnugk.stdout`, `ep-<alias>.stdout` | console output (startup errors, crash messages) |
| `tcpdump.log` | tcpdump's messages, only interesting when the capture failed |

Characters like `[` and `]` in the test name become `_`, eg. `test_call[plain-md5-h245]` writes to
`test/results/test_call_plain-md5-h245_/`. The directory is cleared when the test runs again.

Set `GKTEST_GK_TRACE=7` for more detailed GnuGk traces (default 5), `GKTEST_EP_TRACE` for the
endpoints, and `GKTEST_KEEP_NETNS=1`
to keep the namespaces after the run, eg. to poke around with `ip netns exec gkt-gk ...`.

## When a test fails

The failure report of a test includes what it checks ("what this test checks", from its docstring).

1. **Which test:** the summary at the end lists each failure as
   `FAILED scenarios/test_calls.py::test_call[plain-md5-h245] - AssertionError: ...`.
   The part before ` - ` is the test ID, after it the failed assertion. Most assertions include
   the endpoint result (registered, connected, `endReason`, RTP counters). The full traceback is
   further up; `-v` shows each test name while the tests run.
2. **Rebuild** if you changed GnuGk code (`test/build-deps.sh`, or the quick rebuild above),
   otherwise the tests run the old binary.
3. **Rerun only that test** (quote it, because of the brackets):

   ```bash
   test/run.sh "scenarios/test_calls.py::test_call[plain-md5-h245]"
   test/run.sh --lf                     # only the tests that failed in the last run
   ```

4. **Read its result directory**, in this order:
   - `ep-<alias>.json`: did the endpoint register, did the call connect, why did it end
   - `gnugk.ini`: the config GnuGk really ran with (base config + the test's overrides)
   - `gnugk.trace`: eg. `grep -n -E "RRJ|ARJ|reject|fail" gnugk.trace`, then read around the hit;
     rerun with `GKTEST_GK_TRACE=7` if it's not detailed enough
   - `ep-<alias>.trace`: the endpoint's side of a rejection or a failed call
   - `gk.pcap` (Wireshark or `tcpdump -nn -r gk.pcap`): whether signaling / media flowed, and which way
   - `gnugk.stdout`: if the test says GnuGk exited during the test
5. **Regression or old bug:** run the same test with a GnuGk built before your change (eg. in a
   `git worktree`): `GKTEST_GNUGK=/path/to/old/gnugk test/run.sh "<test id>"`. Passes there and
   fails with yours: your change caused it.

Also:
- Copy the result directory if you want to keep a failed run, the next run of the test clears it.
- **XPASS** is reported as a failure too: a known bug (below) is fixed, remove its `xfail` marker.
- A test that only fails sometimes points at timing; rerun it a few times before digging.

## Known GnuGk issues

Tests for known bugs are marked as expected failures (`pytest.mark.xfail`, most of them in
`KNOWN_BUGS` in `scenarios/test_calls.py`). They are strict: once the bug is fixed the test
reports XPASS as a failure, then remove the marker. Currently:

- With all Q.931 messages checked (`h2351-all`), calls to an H.460.18 callee fail: GnuGk checks the
  Facility the callee sends to open its signaling channel, and has no authenticator for it yet.
- `DisconnectCall` sets no release source (CDR `%r` is -1) and no cause.
- `RerouteCall` with fastStart: no media is opened after the reroute.
- `SQLAuth` `NbQuery`: LRQs from configured neighbors skip all authenticators, the query only runs for
  non-neighbor LRQs (`AcceptNonNeighborLRQ=1`).
- Calls to an H.460.18 traversal client neighbor: the SCI says to connect to 0.0.0.0
  (`GetRasServerIP()` isn't set for neighbors).

## Network

Every host runs in its own network namespace (prefix `gkt-`):

```
gk     10.99.0.1  --+
gk2    10.99.0.2  --+     (a 2nd gatekeeper: neighbor, child)
pub1   10.99.0.11 --+
pub2   10.99.0.12 --+-- bridge (gkt-core)
nat1   10.99.0.21 --+     nat1 192.168.1.1 -- priv1 192.168.1.10
nat2   10.99.0.22 --+     nat2 192.168.2.1 -- priv2 192.168.2.10
```

`nat1` and `nat2` masquerade (iptables) everything from their private network. The bridge
hosts also get IPv6 addresses (`fd00:99::/64`) when the kernel supports IPv6. Every namespace
gets a hosts file with all test hosts and no DNS server (`/etc/netns/gkt-*`), so name lookups
don't wait for DNS timeouts. The public
hosts have no route to the private networks, so a private endpoint is only reachable through
NAT state it created itself, the way H.460.18/.19 is meant to work.

## Layout

```
test/
  build-deps.sh        builds PTLib, H323Plus, GnuGk, addpasswd and the endpoint
  run.sh               runs pytest
  endpoint/            gktestep: small H323Plus endpoint (G.711 tone, MD5/H.235.1, H.460.18, JSON result)
  harness/             topology (namespaces), GnuGk process + config + status port, endpoint runner
  scenarios/           the tests
  conftest.py          pytest fixtures (network, result directory, pcap, GnuGk start/stop)
```

## Adding a test

Scenarios are plain pytest functions, with a docstring that says what they check (shown by `--collect-only` and `-v --describe`;
a module can add a description of the parameters with `describe_params(params)`, see `test_calls.py`). `start_gk(config...)` starts GnuGk with the base config
from `harness/gnugk.py` merged with the given `{section: {key: value}}` dicts (a value of `None`
deletes a key) and stops it after the test, failing the test if GnuGk crashed. `Endpoint(...)`
runs `gktestep` on one of the hosts above. Every endpoint gets its own signaling port (RAS: the next one)
and RTP ports, `listen_port=1720` for an endpoint that is called by IP, `gk=` to register with another
gatekeeper. `harness/calls.py` has `run_call()` for a complete call, the
GnuGk object has helpers for the status port (`registrations()`, `current_calls()`, `StatusSession`
for a persistent connection), the trace (`ras_events()`, `trace_count()`), CDRs (`cdrs()`) and
its resources (`resources()`). A second gatekeeper: `start_gk(config, host="gk2", name="gk2")`.

## gktestep

```
gktestep --gk ip[:port]|--no-gk --alias name[,name...] --result file.json [options]
  --no-gk              don't use a gatekeeper (calls go to the address given with --call)
  --ras-port port      local RAS port (default 1719)
  --rtp-ports min-max  local RTP/RTCP port range
  --bandwidth n        bandwidth to ask for in ARQs (units of 100 bit/s)
  --brq n              caller: send a BRQ for this bandwidth 1 second into the call
  --listen ip[:port]   signaling listener (default *:1720), [ipv6]:port for IPv6
  --password pw        register with H.235 MD5 tokens
  --h2351              use H.235.1 (Procedure I) tokens instead of MD5, also in the call Setup
  --full-q931          with --h2351: put tokens into all Q.931 messages, not only the Setup
  --md5-unsigned list  send these RAS messages without MD5 token (RRQ,URQ,ARQ,BRQ,DRQ,IRR)
  --h46018             use H.460.18/.19 NAT traversal
  --h46019m            with --h46018: use H.460.19 RTP multiplexing (receive and send)
  --no-faststart       open media with H.245 only
  --no-tunneling       use a separate H.245 channel instead of H.245 tunneling
  --call alias         call this alias, otherwise answer one call
  --calls n            caller: make n calls one after the other, callee: answer up to n calls
  --add-alias a[,b]    add these aliases with an additive registration (sent with the next keep-alive RRQ)
  --gateway            register as gateway (prefixes come from the gatekeeper config)
  --reject busy|denied refuse incoming calls as busy (cause 17) or rejected (cause 21)
  --hangup-after sec   callee: hang up an answered call after this time
  --answer-delay sec   callee: ring this long before answering
  --duration sec       how long to keep the call up (caller) or to wait for a call (callee)
  --timeout sec        max. time for registration and call setup (default 10)
  --trace n --log file PTLib trace output
```

It only offers G.711 (built into H323Plus, no codec plugins needed) and sends a 440 Hz tone
without silence suppression, so the RTP packet counters can be compared between the two sides.
