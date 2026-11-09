# Scanners CAWASMA is compared with

These tools are good at finding vulnerabilities, and several find classes CAWASMA
does not look for at all (see `future-coverage.md`). The gap CAWASMA addresses is
narrower: **scoring the same finding differently according to the endpoint it is
on and the data that endpoint returned**.

Everything below comes from each tool's own documentation, read on 2026-11-09.
"Not described" means we found no such feature in the pages linked; it does not
prove the feature is absent.

| Scanner | Type | What it does well | How it rates severity | What it does not do that CAWASMA does |
|---|---|---|---|---|
| **OWASP ZAP** (ZAP by Checkmarx) | Open source, Apache-2.0 ([site](https://www.zaproxy.org/), [repo](https://github.com/zaproxy/zaproxy)) | Passive and active scan rules for specific vulnerabilities ([rules](https://www.zaproxy.org/docs/alerts/)); a passive baseline mode for CI/CD that makes no attacks ([baseline](https://www.zaproxy.org/docs/docker/baseline-scan/)) | Each scan rule has a set risk (High, Medium, Low, Informational), plus a confidence (Low, Medium, High). A user can override risk per alert or with an Alert Filter ([alerts](https://www.zaproxy.org/docs/desktop/start/features/alerts/), [filters](https://www.zaproxy.org/docs/desktop/addons/alert-filters/)) | Automatic re-scoring of a finding from endpoint sensitivity or returned data: not described. Overrides are configured by the user |
| **Nuclei** (ProjectDiscovery) | Open source, MIT ([repo](https://github.com/projectdiscovery/nuclei)); a paid cloud service is built on it | Fast, customisable, template-based scanning; templates reproduce real steps to verify an issue and cut false positives ([repo](https://github.com/projectdiscovery/nuclei), [templates](https://docs.projectdiscovery.io/templates/introduction)) | Each template declares its own `severity` ([structure](https://docs.projectdiscovery.io/templates/structure)): info, low, medium, high, critical or unknown ([CLI help](https://github.com/projectdiscovery/nuclei)) | Changing a template's severity from the endpoint or the response: not described |
| **Nikto** | Open source, GPL-3.0; its database files are under separate terms ([repo](https://github.com/sullo/nikto)) | Web server scanning, with output in CSV, HTML, XML, JSON and SQL ([export formats](https://github.com/sullo/nikto/wiki/Export-Formats)) | No severity rating: its report fields are id, scan id, test id, host details, references, method, URI, message, request and response ([export formats](https://github.com/sullo/nikto/wiki/Export-Formats)) | Any severity or ranking of findings |
| **Burp Suite Professional** (PortSwigger) | Commercial, $499 listed ([product](https://portswigger.net/burp/pro)) | Automated scanning with manual penetration-testing tools in one product ([product](https://portswigger.net/burp/pro)) | Severity (High, Medium, Low, Information) reflecting "the likely impact of each issue for a typical organization", plus confidence (Certain, Firm, Tentative) ([sample report](https://portswigger.net/burp/samplereport/burpscannersamplereport)). Each issue type has a typical severity ([definitions](https://portswigger.net/burp/documentation/desktop/tools/target/issue-definitions)). A user can reassign both ([issues](https://portswigger.net/burp/documentation/desktop/automated-scanning/results/issues)) | Automatic re-scoring from endpoint sensitivity or returned data: not described. Its advisories discuss context in prose, for a person to judge |
| **Acunetix / Invicti** ("Acunetix is now Invicti Web + API") | Commercial ([pricing](https://www.invicti.com/pricing/)) | Proof-based scanning: confirms vulnerabilities "by attempting safe, read-only exploits" ([proof-based](https://www.invicti.com/features/proof-based-scanning/)) | Levels by vulnerability type: Critical, High, Medium, Low, plus Best Practice and Information ([levels](https://www.acunetix.com/support/docs/a360/issues/vulnerability-severity-levels/)); supports CVSS v3.0 ([FAQ](https://www.acunetix.com/support/docs/faqs/what-vulnerability-classifications-does-acunetix-use/)) | Per-finding re-scoring by endpoint context: not described. Predictive Risk Scoring and Business Criticality work at website or target level (below) |

## The closest commercial idea: Invicti Predictive Risk Scoring

Announced by Invicti on 22 April 2024 ([blog](https://www.invicti.com/blog/web-security/predictive-risk-scoring)).
It is the nearest thing we found to our idea, and it solves a different problem:

| | Invicti Predictive Risk Scoring | CAWASMA |
|---|---|---|
| What gets a score | Each discovered **website** | Each **finding on an endpoint** |
| When | **Before** scanning ("an early pre-scan step") | **After** a finding is detected |
| Inputs | Up to 220 public attributes of the site, such as deprecated TLS or the number of form inputs ([docs](https://docs.invicti.com/ie-is/predictive-risk-scoring-introduction)) | The endpoint's sensitivity class and the data signals in its response |
| Output | A prediction of the highest-severity vulnerability on the site, so teams know which sites to scan first | A CVSS v3.1 environmental score, with a vector anyone can recompute |

Invicti says it "is not a substitute for scanning". It decides which site to scan
first; CAWASMA decides which finding to fix first. They are complementary. The
vendor also reports a confidence of at least 83 %, which we have not checked.

Acunetix also lets a user set a per-target **Business Criticality** (Low, Normal,
High, Critical), used to "filter scans and vulnerabilities"
([targets](https://www.acunetix.com/support/docs/wvs/configuring-targets/)). It is
set by a person, for a whole target; the page does not say it changes a finding's
severity.

## What this does and does not show

- CAWASMA does not replace these tools. It runs safe, read-only checks for
  misconfigurations and does not test for injection, XSS or broken object-level
  authorisation.
- We evaluated only ZAP and Nuclei (`comparison.md`). Nikto, Burp and
  Acunetix/Invicti appear here from their documentation only: we did not run them.
