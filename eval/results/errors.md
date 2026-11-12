# CAWASMA errors

- **scored**: 20261111T015128Z
- **commit**: 3675280
- **CAWASMA**: api 1.0.0, {'crawl_depth': 2, 'use_wordlist': True, 'passive_only': False}
- **ZAP**: zaproxy/zap-stable:2.15.0 (baseline; VAmPI: API scan, safe mode)
- **Nuclei**: projectdiscovery/nuclei:v3.9.0, nuclei-templates v10.1.1
- **targets**: reset before the run
- **raw outputs**: eval/results/raw/<tool>/<target>/20261111T015128Z/

False positives go to Atta (detection code); false negatives may be the scanner
or the ground truth: check the target's `observed/*.json` first.

## False positives (0)

None.

## False negatives (8)

- **API-001** (2): crapi `/identity/api/auth/login` (not crawled), vampi `/users/v1/login` (not crawled)
  - *Cause:* [Atta + Asim] Three of the four login endpoints were never crawled (see API-003 for why). On DVWA /login.php, which was crawled, the legacy rule only looks at API-like paths (/api or JSON), and the checks.yaml spec stays unimplemented until Asim says what an "authentication endpoint" is (docs/check-coverage.md).
- **API-003** (4): juice-shop `/ftp/acquisitions.md` (not crawled), juice-shop `/metrics`, juice-shop `/rest/admin/application-configuration` (not crawled), vampi `/books/v1`
  - *Cause:* [Atta] Never crawled. The crawler's JavaScript route extraction only matches quoted "/api/..." paths: Juice Shop's routes are "/rest/..." and crAPI keeps relative "api/..." strings with a separate service prefix. It doesn't read OpenAPI specs (VAmPI publishes /openapi.json), and its wordlist has no /metrics or /ftp. eval/labels/collect_endpoints.py finds all of them, so it is a discovery gap, not a detection one.
- **INF-002** (2): juice-shop `/encryptionkeys` (not crawled), juice-shop `/ftp`
  - *Cause:* [Atta + Asim] Never crawled: /config/, /docs/ (DVWA) and /ftp, /encryptionkeys (Juice Shop) are not linked from crawled pages and not in the wordlist. Juice Shop's listings would still be missed: the checks.yaml regex knows only Apache's "Index of /", not serve-index's "listing directory" (noted in ground_truth/juice-shop.yaml).
