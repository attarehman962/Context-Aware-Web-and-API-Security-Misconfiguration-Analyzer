# CAWASMA — Documentation

**Context-Aware Web & API Security Misconfiguration Analyzer**
Final Year Project, BS Computer Science, FAST-NUCES Islamabad.
Team: Atta Ur Rehman (backend & engine), Neelam (frontend), Asim (security, ML & evaluation).

### Start here: plan and requirements

The team's planning documents (SRS, development plans, project summaries,
per-partner prompts) are in [project/](project/README.md). **The SRS is the
reference** for what we are building; the documents below describe the system
as implemented so far, which still differs from the SRS in places (notably the
scoring formula).

### Implementation documentation

Each file is self-contained; start with the Overview and follow the order below.

| # | Document | What it covers |
|---|----------|----------------|
| 01 | [Overview](01-overview.md) | What CAWASMA is, the problem, the research gap, the novelty |
| 02 | [Architecture](02-architecture.md) | System design, process topology, data flow, technology choices |
| 03 | [Installation & Running](03-installation.md) | Setup with and without Docker, configuration, tests |
| 05 | [Security Checks (all 58)](05-security-checks.md) | Every check with its category, CVSS vector and base score |
| 06 | [Scoring Model](06-scoring-model.md) | CVSS v3.1 environmental scoring, and the interim formula the legacy checks still use |
| 07 | [Novel Contributions](07-novel-contributions.md) | The three contributions, in depth |
| 08 | [Database Schema](08-database-schema.md) | Tables, relationships, cascades |
| 09 | [Attack Chains](09-attack-chains.md) | The five chain templates and how they fire |
| 10 | [Limitations & OWASP Coverage](10-limitations-owasp.md) | Honest black-box limits, OWASP API mapping |
| 11 | [Viva Guide](11-viva-guide.md) | Likely questions and concise answers |

### Team contracts (Sprint 1)

| Document | For | What it covers |
|----------|-----|----------------|
| [API contract v1](api-contract.md) + [openapi.json](openapi.json) | Neelam | Public endpoints, examples, errors, status values, mock mode |
| [Check spec format](check-spec-format.md) | Asim | `config/checks.yaml` fields, CVSS vector rules, validator |
| [CVSS mapping contract](cvss-mapping-contract.md) | Asim | `classify` / `analyze` interfaces, `cvss_mapping.yaml`, `chains.yaml` |
| [Schema](schema.md) · [DB decisions](db-decisions.md) | everyone | Tables, ER diagram, design decisions |
| [Engine safety](engine-security.md) | everyone | SSRF rules, DNS-rebinding defence, passive mode, eval allow-list |
| [Adding a check](adding-a-check.md) | Atta, Asim | From a checks.yaml spec to a registered, tested check |

### Security, ML and evaluation notes (Asim)

| Document | What it covers |
|----------|----------------|
| [CVSS mapping](cvss-mapping.md) | Sensitivity class / body signal → CR, IR, AR rows with justifications and worked examples |
| [Check specs review](check-specs-review.md) | Every check in `config/checks.yaml` by score, with debatable vectors |
| [Chain templates](chain-templates.md) | The five attack chains: trigger logic, evidence, weak spots |
| [Labelling guide](labelling-guide.md) | Definitions and examples for the four sensitivity classes |
| [Literature review](lit-review.md) | Notes on CVSS, OWASP and related scanners |

### Process: prompts and reviews

| Document | What it covers |
|----------|----------------|
| [Code walkthrough](walkthrough.md) | Each main module in a few lines: how it works, why, who owns it |
| [Prompts](prompts/README.md) | The 30 Claude Code prompts we ran, one per branch |
| [Reviews](reviews/) | Atta's reviews of partner prompts, and the [final audit](reviews/final-audit.md) before submission |
| [Security review](security-review.md) · [Evaluation method](evaluation-method.md) · [Performance](performance.md) · [Check coverage](check-coverage.md) | The tool's own security review, how it was evaluated, scan timings, tests per check |

### Related files (project root)

- **[README.md](../README.md)**: quick project summary and quick start
- **[CLAUDE.md](../CLAUDE.md)**: ownership, conventions and commands for the team

### At a glance

- **Type:** defensive, black-box, HTTPS-only web & REST-API misconfiguration scanner
- **Core novelty:** context-aware risk prioritization (not just "find bugs")
- **Checks:** 62 check ids across 7 categories (58 in the catalog, 25 with a
  `checks.yaml` spec), each with a predefined CVSS v3.1 base vector
- **Contributions:** (1) NLP endpoint sensitivity classification, (2) attack-chain
  correlation, (3) response-body sensitivity classification
- **Stack:** FastAPI · PostgreSQL · Redis · Celery · httpx · SQLAlchemy ·
  sentence-transformers · WeasyPrint · Next.js frontend
- **Tests:** about 940 backend tests (unit, checks, API, integration, database,
  security, eval tooling) and the frontend's Vitest and Playwright suites
  (`make test`, `npm test`, `npm run test:e2e`)
