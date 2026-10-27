# Response-body classifier

`backend/app/ml/body_classifier.py` (owner: Asim). Contract function:
`analyze(response) -> set[BodySignal]` (docs/cvss-mapping-contract.md, unchanged).
`detect(response) -> list[Detection]` returns what was found, with the rule
that matched and **redacted** evidence.

## Kinds and signals

| kind | BodySignal | rules |
|------|------------|-------|
| `credential` | `CREDENTIALS` | `json-password-field`, `html-password-input`, `env-password` (`DB_PASSWORD=...`), `http-basic-auth` (decodes to `user:pass`), `connection-string` (`postgres://u:p@host`, ADO `Server=...;Password=...`), `url-credentials` |
| `secret_key` | `CREDENTIALS` | `aws-access-key-id`, `aws-secret-access-key`, `private-key-pem` (not public keys), `jwt` (header must decode to JSON with `alg`), vendor keys (Stripe live, GitHub, Slack, Google, SendGrid, npm), `generic-api-key` (`*key`/`*token`/`*secret` = value of 16+ chars, letters and digits, Shannon entropy ≥ 3.5 bits/char) |
| `pii` | `PII` | `email`, `phone` (international, NANP, Pakistan mobile `03xx-xxxxxxx`), `national-id-cnic` (`35202-4567891-3`), `national-id-ssn`, `person-name` (spaCy NER, see below) |
| `financial` | `FINANCIAL` | `card-number` (brand prefix + length + Luhn), `iban` (ISO 13616 mod-97) |
| `internal_ip` | `INTERNAL_IP` | `rfc1918`, `loopback`, `link-local` (incl. 169.254.169.254), IPv6 `ula`/link-local/`::1` |
| `stack_trace` | none | Python, Java, PHP, .NET, Node (also HTML error pages such as Express's) |

`secret_key` and `stack_trace` are not new `BodySignal`s: `BodySignal` is also
an enum in the frozen API contract, so adding values needs Atta's and Neelam's
agreement. Secrets raise the same CVSS requirements as credentials; a stack
trace is a disclosure finding (API-004), not sensitive data, so it raises none.

**Regex first, spaCy only where regex can't**: a value under a name-like JSON
key (`full_name`, `first_name`, `name`, ...) counts as a person name only if
the same object has a personal field within 400 characters (email, phone,
address, date of birth, CNIC/SSN, passport) **and** spaCy's
`en_core_web_sm` tags it `PERSON`. At most 20 candidates per body go to spaCy
(about 5 ms each). Without spaCy (`INSTALL_ML=false`) only this rule is off.

## Evidence is redacted

| what | stored / shown as |
|------|-------------------|
| keys, tokens | first 4 + `****` + last 4: `AKIA****WXYZ`; short values `****` |
| passwords | always `****`, never partial: `"password": "****"`, `DB_PASSWORD=****` |
| JWT | `eyJhbG****.****.****` |
| connection strings | `postgres://app:****@db.internal:5432` |
| emails | first letter + domain: `a***@shopmail.pk` |
| phones, CNIC, SSN | last digits only: `**********67`, `*****-*******-3` |
| cards, IBANs | `****1234`, `PK******5101` |
| stack traces | first frame, run through `utils/redaction.py` |
| internal IPs | shown: an address is topology, not a secret |

The tests assert that no fixture secret appears in any evidence.

## Placeholders are ignored

Placeholders are nobody's data; reporting them would raise the score of every
documentation page.

- **Emails** at reserved domains (RFC 2606/6761: `example.*`, `*.test`,
  `*.invalid`, `*.localhost`) and stock ones (`test@test.com`,
  `user@domain.com`); **organisational mailboxes** (`security@`, `privacy@`,
  `support@`, `no-reply@`, ...), which are published on purpose; addresses an
  app already masked (`***in@shop.com`); image names like `logo@2x.png`.
- **Emails in JSON display copy**: inside a prose value (5+ words) under
  `description`, `hint`, `text`, `help`, `title`, `label`, `tooltip`, `message`,
  `instructions` or `summary` (Juice Shop's challenge texts name its demo
  accounts). Trade-off: a user's email typed into a free-text `message` is
  missed. `"email": "..."` fields, other keys and HTML pages are unaffected.
- **Cards**: published payment-provider test numbers (`4111 1111 1111 1111`,
  `4242 4242 4242 4242`, `5555 5555 5555 4444`, ...): they are test data
  wherever they appear. Example IBANs from ISO/bank documentation.
- **Keys**: AWS documentation keys (anything containing `EXAMPLE`); template or
  mask values (`your_api_key`, `${TOKEN}`, `<password>`, `{{x}}`, `****`,
  `changeme`, `null`, `aaaa`).
- **Password labels**: `"PASSWORD": "Password"`, `"Forgot your password?"`
  (translation files).
- **Phones/IDs**: fictional `555-01xx`, repeated or sequential digits,
  `12345-1234567-1`, documentation SSNs.

## Scope and speed

Only text-like content types are scanned (`text/*`, JSON, XML, JavaScript,
form data, YAML, CSV, GraphQL). `application/octet-stream` and missing types
are sniffed and skipped if binary: crAPI serves its `/.env` as octet-stream.
At most 512,000 characters are read. Every detector has a cheap substring
pre-check, and no pattern has an unbounded prefix (the generic-key rule is
keyword-first), so a 150 KB body takes well under the contract's 50 ms.

## Evaluation run (2026-10-27)

The 164 collected endpoints (`eval/labels/endpoints_raw.csv`) plus 7 known
sensitive responses (crAPI `/.env`, Juice Shop error pages, a VAmPI user),
fetched with GET from the four pinned targets (VAmPI after `/createdb`). 169
responses, 160 text-like. Per call: median 0.1 ms, p95 4.3 ms, max 49 ms
(Juice Shop `/api/Hints`, 98 KB). Each hit's context was checked by hand.

| signal (kind) | hits | in responses | look like false positives |
|---------------|-----:|-------------:|---------------------------|
| CREDENTIALS (`credential`) | 4 | 3 | 0: password hashes in Juice Shop `/rest/memories` and VAmPI `/users/v1/_debug`; `DB_PASSWORD`, `MONGO_DB_PASSWORD` in crAPI `/.env` |
| CREDENTIALS (`secret_key`) | 2 | 1 | 0: users' `deluxeToken` in Juice Shop `/rest/memories` |
| PII (`pii`) | 13 | 6 | **4**: account emails quoted in challenge descriptions (`/api/Challenges` ×3, `/api/Hints` ×1); the other 9 are user records |
| FINANCIAL (`financial`) | 0 | 0 | none (no card or IBAN data in these targets' unauthenticated responses) |
| INTERNAL_IP (`internal_ip`) | 2 | 2 | 0, but low value: `127.0.0.1` as the DB host in DVWA `config.inc.php.dist` and on `setup.php` |
| none (`stack_trace`) | 14 | 13 | 0: Juice Shop's 500 pages leak server file paths |

Tuning applied during the run: role mailboxes and app-masked emails are
ignored (removed 4 false positives from `security.txt` and the app
configuration), `mail.com` is a real provider (VAmPI's user emails now count),
octet-stream bodies are sniffed (crAPI `/.env` was missed), and HTML stack
frames are recognised (all 14 traces were missed).

Second pass, same responses, after adding the JSON display-copy rule: the
4 PII false positives are gone; PII is now **9 hits, 0 false positives**,
everything else unchanged. Still open: loopback could carry a lower weight
than RFC 1918.

## Not wired in yet

The scan pipeline (`core/pipeline.py`, Atta) still calls the built-in
`core/body_classifier.classify_body`, not `app.ml.body_classifier.analyze`.
Until it switches, scans use the built-in classifier; this module is used by
the eval and by anyone calling the contract function.
