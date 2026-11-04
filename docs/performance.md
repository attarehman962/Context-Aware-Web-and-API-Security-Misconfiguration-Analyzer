# Scan performance

Budget: a full scan of a typical target in **under 10 minutes**. Every scan
records seconds per stage in `ScanResult.stats["stage_seconds"]` (logged with
the scan id when it completes) and the number of requests sent.
`python -m scripts.profile_scan URL` prints them for one scan.

| stage | what it times |
|-------|---------------|
| `setup` | classifiers (the ML models load once per process) |
| `seed` | first GET of the target |
| `crawl` | discovery: HTML/JS/OpenAPI, BFS, wordlist |
| `tls` | TLS analysis (SSLyze, once per host; runs alongside the crawl) |
| `http_probe` | plain-HTTP probe for TLS-005 (alongside the crawl) |
| `endpoints` | per-endpoint GET, probes, checks, scoring |
| `scoring` | host findings, chain correlation |
| `total` | whole scan |

## Before and after (2026-11-04)

Juice Shop, DVWA and VAmPI from `docker-compose.eval.yml`, scanned from a
container on the eval network, with the harness options (depth 2, wordlist on,
active probes). The targets are plain HTTP here, so `tls` is ~0. One run each,
same machine.

| target | version | total s | setup | crawl | endpoints | requests | endpoints found | findings |
|--------|---------|--------:|------:|------:|----------:|---------:|----------------:|---------:|
| Juice Shop | before | 191.0 | ~188 | 0.3 | 1.6 | 93 | 15 | 138 |
| Juice Shop | after | **8.0** | 3.9 | 0.3 | 3.6 | 288 | 57 | 577 |
| DVWA | before | 0.4 | ~0.1 | 0.0 | 0.2 | 42 | 4 | 56 |
| DVWA | after | 0.7 | 0.1 | 0.3 | 0.3 | 69 | 8 | 106 |
| VAmPI | before | 1.2 | ~0.1 | 0.1 | 0.8 | 30 | 2 | 25 |
| VAmPI | after | 1.4 | 0.1 | 0.1 | 1.1 | 64 | 7 | 80 |

"Before" is commit 86be81d with only the timers added. "After" finds 2–4×
as many endpoints (the discovery fixes below), so the totals aren't like for
like: the per-endpoint cost is the fairer comparison. On Juice Shop it is
0.107 s before and 0.063 s after (−41 %).

What changed:

1. **Offline model loading** (`HF_HUB_OFFLINE=1` in the image). The models are
   baked in at build time, but sentence-transformers still asked huggingface.co
   for updates and retried for about 3 minutes on a network without internet,
   as the eval network is. This was almost all of the 191 s.
2. **Request de-duplication**: a per-scan cache in `HttpEngine.fetch` for plain
   GET/HEAD. Concurrent identical requests share one in-flight request. Before,
   the seed was fetched 3 times and every crawled page twice. Probes with
   headers, and OPTIONS, are never cached.
3. **Concurrency**: endpoints are analysed 8 at a time
   (`MAX_CONCURRENT_ENDPOINTS`), and each endpoint's four probes are sent
   together. TLS and the plain-HTTP probe run while the crawl does. Each crawl
   level is fetched concurrently, and so is the wordlist. The engine's semaphore
   (`MAX_CONCURRENT_REQUESTS`, 10) and its single HTTP/2 connection pool still
   bound the load on the target. Results are assembled in discovery order, so
   they don't depend on timing (tested).
4. **TLS stays once per host** (unchanged): SSLyze runs once per scan.

Worst case by the caps: 200 endpoints × ~5 requests at 10 in flight, with a
15 s timeout per request. Measured at 0.06 s per endpoint, that is about 15 s of
endpoint analysis, well inside the budget. `SCAN_TIMEOUT` (20 min) stops a
pathological target.
