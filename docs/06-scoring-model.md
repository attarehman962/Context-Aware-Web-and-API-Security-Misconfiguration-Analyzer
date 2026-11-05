# 06 — Scoring Model

This is the heart of CAWASMA's novelty. Two numbers are produced for every
finding and kept **strictly separate**:

1. the official **CVSS v3.1 base score** (predefined per rule, unchanged), and
2. the CAWASMA **context-aware final score** (custom prioritization metric).

CAWASMA never claims the final number is an official CVSS score.

## CVSS v3.1 environmental scoring

Implemented in `backend/app/core/cvss.py` (`environmental_score`,
`score_finding`), as the SRS requires. The pipeline scores the 20 spec-registry
checks this way (`final_vector` and `score_reasons` are stored); the 42 legacy
catalog rules still use the interim formula below until they move to
`config/checks.yaml` (`docs/check-coverage.md`).

1. Start from the check's official CVSS v3.1 **base** vector (`checks.yaml`).
2. Look up the endpoint's sensitivity class and the response's body signals in
   `config/cvss_mapping.yaml` (Asim's file). Each gives Security Requirements
   `CR`, `IR`, `AR`. Signals can only **raise** a requirement; per requirement
   the highest value wins (`L < M < H`, `X` adds nothing).
3. Append `/CR:../IR:../AR:..` to the base vector and compute the CVSS v3.1
   **environmental** score with the `cvss` library. No modified base metrics
   are used, so the result is a standard vector anyone can recompute in the
   FIRST calculator.

Example: `HDR-001` Missing HSTS, base vector
`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N`:

| Sensitivity | Signals | Requirements | Base | Environmental |
|-------------|---------|--------------|-----:|--------------:|
| `LOW` | — | `CR:X/IR:X/AR:X` | 5.3 | **5.3** (Medium) |
| `MEDIUM` | — | `CR:M/IR:M/AR:M` | 5.3 | **5.3** (Medium) |
| `HIGH` | — | `CR:H/IR:M/AR:M` | 5.3 | **7.1** (High) |
| `LOW` | `CREDENTIALS` | `CR:H/IR:H/AR:M` | 5.3 | **7.1** (High) |
| `CRITICAL` | — | `CR:H/IR:H/AR:H` | 5.3 | **7.1** (High) |

The result also carries `score_reasons`, e.g. `["sensitivity:HIGH",
"signal:PII", "CR:H<-sensitivity:HIGH+signal:PII", "IR:M<-sensitivity:HIGH+signal:PII",
"AR:M<-sensitivity:HIGH", "base:9.1", "environmental:9.8"]`, for the frontend
drill-down. Severity uses the v3.1 ranges (None 0.0, Low 0.1–3.9, Medium
4.0–6.9, High 7.0–8.9, Critical 9.0–10.0; "None" is stored as `INFO`).

Guarantees, enforced by `backend/tests/unit/test_cvss_environmental.py` for
every check vector, class and signal combination: the score matches an
independent implementation of the FIRST equations, it never goes down as
sensitivity rises or signals are added, and the vector re-parses to the same
score.

## Interim formula (legacy catalog rules)

```
Final score = min( 10.0 , (CVSS base × Context multiplier) + Response bonus )
```

### Context multipliers (by endpoint sensitivity)

| Endpoint context | Multiplier |
|------------------|:----------:|
| CRITICAL | × 2.0 |
| HIGH | × 1.5 |
| MEDIUM | × 1.0 |
| LOW | × 0.6 |

### Response bonuses (by what the response exposes)

| Response signal | Bonus |
|-----------------|:-----:|
| Credentials | + 3.5 |
| PII | + 2.0 |
| Financial data | + 1.5 |
| Internal / infra IP | + 2.0 |

(Values live in `backend/app/core/cvss.py` as `CONTEXT_MULTIPLIERS` and
`RESPONSE_BONUS`.)

## Severity buckets

The final score maps to a severity:

| Score range | Severity |
|-------------|----------|
| 9.0 – 10.0 | CRITICAL |
| 7.0 – 8.9 | HIGH |
| 4.0 – 6.9 | MEDIUM |
| 0.1 – 3.9 | LOW |
| 0.0 | INFO |

**Special rule:** if the response body contains **credentials**, the finding's
severity is forced to **CRITICAL** regardless of the arithmetic.

## Worked examples

**Example 1 — same finding, sensitive endpoint**
Finding: *Missing X-Frame-Options* (base 6.1) on `/api/payment/checkout`
(context CRITICAL), response contains PII + financial data (bonus +2.0 used).

```
6.1 × 2.0 = 12.2
12.2 + 2.0 = 14.2
min(10.0, 14.2) = 10.0  →  CRITICAL
```

**Example 2 — same finding, trivial endpoint**
Finding: *Missing X-Frame-Options* (base 6.1) on `/about` (context LOW), no
sensitive response.

```
6.1 × 0.6 = 3.66  →  rounded 3.7  →  LOW
```

Identical vulnerability, final scores of **10.0** vs **3.7** — this is the
prioritization conventional scanners miss.

## What is stored (kept distinguishable)

Each finding row stores all of these separately, so the standard and the custom
values can never be confused:

```
cvss_vector                 e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
base_score                  e.g. 6.1   (official)
cawasma_context_multiplier  e.g. 2.0   (custom)
response_bonus              e.g. 2.0   (custom)
final_score                 e.g. 10.0  (custom)
severity_bucket             e.g. CRITICAL
```

## Findings vs. attack chains

A **finding** is a single issue with its own context-aware score. An **attack
chain** is a *separate* record with a documented **template composite score**
(a known pattern's severity), and it fires only when its member findings are
actually detected. The two are stored and reported separately and must not be
conflated — see [Attack Chains](09-attack-chains.md).
