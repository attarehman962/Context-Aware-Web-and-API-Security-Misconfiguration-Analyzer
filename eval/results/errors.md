# CAWASMA errors

- **CAWASMA**: 1.0.0
- **raw outputs**: eval/results/raw/<tool>/<target>/20261104T152231Z/
- **ZAP**: 2.15.0 zaproxy/zap-stable@sha256:8dc78e39fafc3281ac2cf54eab05c3ea02721a1ea58f1c135f981a57f4e218b1
- **Nuclei**: v3.9.0 projectdiscovery/nuclei@sha256:66b5f88c9b98ad29c03343dd34e5e85bde0ad10428d72e0171b067efe1ed7811 nuclei-templates v10.1.1

False positives go to Atta (detection code); false negatives may be the scanner
or the ground truth: check the target's `observed/*.json` first.

## False positives (4)

- **API-001** (3): vampi `/`, vampi `/books/v1`, vampi `/openapi.json`
  - *Cause:* [Atta + Asim] The legacy rule fires on any API-looking endpoint without rate-limit headers (VAmPI /, /books/v1, /openapi.json); the checks.yaml spec applies to authentication endpoints only, which the spec format can't yet express (docs/check-coverage.md: needs a path or sensitivity scope in core/specs.py). Proposed answer: endpoints classed HIGH whose path has an auth token (login, signin, token, otp, password, reset).
- **API-003** (1): vampi `/openapi.json`
  - *Cause:* [Atta + Asim] The legacy rule treats VAmPI's /openapi.json, published API documentation, as an unauthenticated data collection. Proposed answer to the spec question: sensitive = HIGH or CRITICAL, and never an API description document (INF-006 already reports those).

## False negatives (9)

- **API-001** (4): crapi `/identity/api/auth/login` (not crawled), dvwa `/login.php`, juice-shop `/rest/user/login`, vampi `/users/v1/login` (not crawled)
  - *Cause:* [Atta + Asim] Three of the four login endpoints were never crawled (see API-003 for why). On DVWA /login.php, which was crawled, the legacy rule only looks at API-like paths (/api or JSON), and the checks.yaml spec stays unimplemented until Asim says what an "authentication endpoint" is (docs/check-coverage.md).
- **API-003** (3): juice-shop `/ftp/acquisitions.md` (not crawled), juice-shop `/metrics`, juice-shop `/rest/admin/application-configuration` (not crawled)
  - *Cause:* [Atta] Never crawled. The crawler's JavaScript route extraction only matches quoted "/api/..." paths: Juice Shop's routes are "/rest/..." and crAPI keeps relative "api/..." strings with a separate service prefix. It doesn't read OpenAPI specs (VAmPI publishes /openapi.json), and its wordlist has no /metrics or /ftp. eval/labels/collect_endpoints.py finds all of them, so it is a discovery gap, not a detection one.
- **INF-002** (2): juice-shop `/encryptionkeys` (not crawled), juice-shop `/ftp`
  - *Cause:* [Atta + Asim] Never crawled: /config/, /docs/ (DVWA) and /ftp, /encryptionkeys (Juice Shop) are not linked from crawled pages and not in the wordlist. Juice Shop's listings would still be missed: the checks.yaml regex knows only Apache's "Index of /", not serve-index's "listing directory" (noted in ground_truth/juice-shop.yaml).
