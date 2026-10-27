# Scan engine safety: SSRF, DNS rebinding, passive mode

How CAWASMA's HTTP engine (`backend/app/core/engine.py`) and SSRF guard
(`backend/app/utils/security.py`) keep the scanner from being used against
internal infrastructure. Tests: `backend/tests/unit/test_ssrf_guard.py` and
`test_engine_safety.py`.

## The rule: decide on IP addresses, never on hostname strings

Every request goes through two independent checks.

1. **Before sending** (`validate_url_ssrf`): the URL's host is turned into IP
   addresses (decoded if it is an IP literal, resolved if it is a name) and
   **every** address must be allowed. This runs for the first URL and again
   for **each redirect hop**: redirects are followed manually
   (`follow_redirects=False`), so a public page that answers
   `302 Location: http://169.254.169.254/` never gets its target fetched.
2. **When connecting** (`PinnedNetworkBackend`): see *DNS rebinding* below.

The TLS probe (`core/tls.py`) opens raw sockets outside httpx, so it applies
the same rule itself: it resolves and validates the host, then connects to the
validated IP (on the target's own port). SSLyze, which enumerates protocols and
cipher suites, is given that IP explicitly (`ServerNetworkLocation(ip_address=...)`),
so it never does its own DNS lookup.

**Active probes stay on the target's origin.** The wordlist, OPTIONS, CORS and
injection probes call `fetch(..., same_origin_only=True)`: a redirect to
another host is reported, not followed, so a probe never reaches a host the
user did not authorise.

Blocked, whatever the encoding:

| Range | Examples |
|-------|----------|
| Loopback | `127.0.0.0/8`, `::1`, `localhost` |
| Private | `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` |
| Link-local | `169.254/16`, `fe80::/10` |
| Cloud metadata (always named explicitly) | `169.254.169.254`, `fd00:ec2::254`, `169.254.170.2` (ECS), `100.100.100.200` (Alibaba) |
| Multicast, unspecified, reserved | `224/4`, `ff00::/8`, `0.0.0.0`, `::`, `240/4` |
| Other non-global | carrier-grade NAT `100.64/10`, documentation and benchmarking ranges |
| IPv6 forms of the above | IPv4-mapped `::ffff:127.0.0.1`, NAT64 `64:ff9b::7f00:1` (the embedded IPv4 is checked) |

**Encoded IP literals** are decoded the way `inet_aton` (and so browsers and
curl) read them, then checked without DNS: decimal `2130706433`, hex
`0x7f000001`, octal `017700000001`, dotted octal `0177.0.0.1`, dotted hex
`0x7f.0.0.1`, short `127.1`. All of them mean `127.0.0.1`.

## DNS rebinding

The attack: a name resolves to a public address when the scanner checks it,
then to `127.0.0.1` a moment later when the HTTP client connects (a TTL-0
record that alternates). Checking the URL first is not enough on its own,
because the client does its own lookup.

The defence: **the connection itself is pinned to a validated address.** httpx
uses httpcore, and httpcore opens every TCP connection through a "network
backend". CAWASMA installs `PinnedNetworkBackend`, whose `connect_tcp(host,
port)`:

1. resolves `host` itself,
2. validates **every** returned address (same rules as above), and
3. asks the real backend to connect to a **validated IP**, not to the name.

So the address that passed the check is the address the socket connects to;
there is no second lookup for an attacker to answer differently. TLS is
unaffected: httpcore passes the original hostname separately for SNI and
certificate verification, so certificates are still checked against the name.

Supporting choices:

- **Every new connection** goes through the backend, including connections
  opened for redirect hops. Kept-alive connections are reused only for the
  same host and port, and so for the same pinned IP.
- **`trust_env=False`**: proxy environment variables are ignored, because a
  proxy would do its own DNS lookup and bypass the pinning.
- **Unix sockets** are refused outright.
- httpx does not expose the network backend publicly, so the engine sets it on
  the transport's pool. `test_http2_and_pinned_backend_are_configured` fails if
  an httpx or httpcore upgrade stops honouring it.

## `ALLOWED_INTERNAL_HOSTS` (evaluation only)

Comma-separated hostnames, **empty by default**, that may resolve to *private*
ranges, so the evaluation targets on the `cawasma-eval` Docker network
(`juice-shop`, `dvwa`, `vampi`, `crapi-web`) can be scanned. Matching is by
exact hostname, case-insensitive. Even for a listed host, loopback,
link-local, cloud metadata, multicast, unspecified and reserved addresses
stay blocked. Set it only through `docker-compose.eval-scan.yml`, never in the
normal `.env`.

`allow_private=True` (engine and pipeline) is a separate, **test-only** switch
that lets the test suite reach its local mock server.

## `SCAN_CA_BUNDLE` (demo and eval only)

Path to a PEM file of extra CA certificates, **empty by default**. The engine
always verifies certificates; this only adds trust anchors on top of the
system store, so a self-signed demo or eval target can be scanned over HTTPS
without turning verification off. `docker-compose.demo.yml` sets it to the
demo target's certificate; never point it at a bundle you don't control.

## Passive mode

`HttpEngine(passive_only=True)` refuses every method except GET and HEAD
before anything is sent; the result carries the error "Blocked by passive
mode". A scan with `passive_only` (ScanRequest) runs with such an engine,
skips the wordlist probe, and skips the active probes (TLS probe, rate-limit
burst, HTTP-redirect check, OPTIONS/CORS preflights).

## Other limits

| Limit | Setting | Default |
|-------|---------|---------|
| Concurrent requests (semaphore) | `MAX_CONCURRENT_REQUESTS` | 10 |
| Timeout per request | `REQUEST_TIMEOUT` | 15 s |
| Retries for transient network errors (GET/HEAD/OPTIONS only) | `REQUEST_RETRIES` | 1 |
| Response body read | `MAX_RESPONSE_SIZE` | 5 MB (rest discarded, `truncated=True`) |
| Redirect hops | `MAX_REDIRECTS` | 5 |
| Pages the crawler fetches | `MAX_CRAWL_PAGES` | 50 |
| Crawl depth | `MAX_CRAWL_DEPTH` | 2 (max 4) |

## Known gaps

- The eval targets serve plain HTTP, while scan targets must be HTTPS; scanning
  them also needs a TLS front on the eval network (review asim-p04, row 7).
- Redirects to `file:`, `gopher:` and other schemes can't be followed: httpx
  only speaks HTTP(S), and scan targets must be `https://`.
