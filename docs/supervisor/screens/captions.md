# Screenshot captions

Taken on 9 November 2026 from a fresh scan of the VAmPI test target (`https://vampi-tls/`, 68 findings), on the app built from `main` at `4051a16`. 1920x1080 at device scale 2.

- `01-new-scan.png`: The new-scan form with the target filled in and the required permission confirmation ticked.
- `02-live-scan.png`: The scan in progress, 12 % done, with its stage, elapsed time and endpoints found updating live.
- `03-results-context.png`: Results for VAmPI: severity summary (3 critical, 2 high, 53 medium, 10 low), 9 findings moved up and 3 down by context, and the list ranked by context-aware score.
- `04-rank-by-base.png`: The same findings with "Base score" selected, showing the plain CVSS order; the secrets finding that context ranks first drops to fourth.
- `05-finding-drilldown.png`: One finding opened: API-003 on `/users/v1/_debug` goes from 9.1 to 9.8, with the CVSS vector, the endpoint class (Authentication, high) and the data found in the response (credentials, personal data).
- `07-pdf-report.png`: First page of the PDF report for the same scan, centred on a grey 16:9 background.
- `08-scan-history.png`: Scan history, filtered with the search box to the local test targets.

There is no `06` (attack chain): this VAmPI scan produced no chains. In the evaluation, chains appear only on DVWA (C001) and crAPI (C005).
