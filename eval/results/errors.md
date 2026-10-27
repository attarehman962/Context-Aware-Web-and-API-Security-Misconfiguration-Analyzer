# CAWASMA errors

- **scored**: 20261027T135320Z
- **CAWASMA**: 1.0.0
- **raw outputs**: eval/results/raw/<tool>/<target>/20261027T133934Z/
- **ZAP**: 2.15.0 zaproxy/zap-stable@sha256:8dc78e39fafc3281ac2cf54eab05c3ea02721a1ea58f1c135f981a57f4e218b1
- **Nuclei**: v3.9.0 projectdiscovery/nuclei@sha256:66b5f88c9b98ad29c03343dd34e5e85bde0ad10428d72e0171b067efe1ed7811 nuclei-templates v10.1.1

False positives go to Atta (detection code); false negatives may be the scanner
or the ground truth: check the target's `observed/*.json` first.

## False positives (0)

None.

## False negatives (17)

- **API-001** (4): crapi `/identity/api/auth/login` (not crawled), dvwa `/login.php`, juice-shop `/rest/user/login` (not crawled), vampi `/users/v1/login` (not crawled)
  - *Cause:* [Atta + Asim] Three of the four login endpoints were never crawled (see API-003 for why). On DVWA /login.php, which was crawled, the legacy rule only looks at API-like paths (/api or JSON), and the checks.yaml spec stays unimplemented until Asim says what an "authentication endpoint" is (docs/check-coverage.md).
- **API-003** (6): juice-shop `/ftp/acquisitions.md` (not crawled), juice-shop `/metrics` (not crawled), juice-shop `/rest/admin/application-configuration` (not crawled), vampi `/books/v1` (not crawled), vampi `/users/v1/_debug` (not crawled), vampi `/users/v1` (not crawled)
  - *Cause:* [Atta] Never crawled. The crawler's JavaScript route extraction only matches quoted "/api/..." paths: Juice Shop's routes are "/rest/..." and crAPI keeps relative "api/..." strings with a separate service prefix. It doesn't read OpenAPI specs (VAmPI publishes /openapi.json), and its wordlist has no /metrics or /ftp. eval/labels/collect_endpoints.py finds all of them, so it is a discovery gap, not a detection one.
- **CKI-001** (1): dvwa `/login.php`
  - *Cause:* [Atta] Engine bug, reproduced: the httpx client keeps a cookie jar across the scan. DVWA sets PHPSESSID on the first response (the / redirect); every later request sends it back, so /login.php never sets it again. The cookie set on the redirect hop itself is dropped too, because only the final response is kept. The scanner should not carry cookies between requests, and should look at Set-Cookie on every redirect hop.
- **CKI-002** (1): dvwa `/login.php`
  - *Cause:* [Atta] Same cookie-jar cause as CKI-001.
- **CKI-003** (1): dvwa `/login.php`
  - *Cause:* [Atta] Same cookie-jar cause as CKI-001.
- **INF-002** (4): dvwa `/config` (not crawled), dvwa `/docs` (not crawled), juice-shop `/encryptionkeys` (not crawled), juice-shop `/ftp` (not crawled)
  - *Cause:* [Atta + Asim] Never crawled: /config/, /docs/ (DVWA) and /ftp, /encryptionkeys (Juice Shop) are not linked from crawled pages and not in the wordlist. Juice Shop's listings would still be missed: the checks.yaml regex knows only Apache's "Index of /", not serve-index's "listing directory" (noted in ground_truth/juice-shop.yaml).
