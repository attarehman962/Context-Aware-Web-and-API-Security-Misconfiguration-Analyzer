# eval/

Evaluation of detection and scoring accuracy (owner: Asim).

Suggested layout:

- `targets/`: Dockerfiles/config for deliberately misconfigured apps
- `ground_truth/`: expected findings, classes, and scores for each target
- `labels/`: labelled endpoint and response examples for ML evaluation
- `harness/`: runners and metric computation code
- `results/`: generated evaluation outputs and reports
- `notebooks/`: exploratory analysis notebooks and figures

The scanner is HTTPS-only and blocks private IPs (SSRF guard); see the notes in
`docker-compose.eval.yml` for how eval scans reach the targets.

## Running the target lab

```bash
make eval-up
python eval/labels/collect_endpoints.py
python eval/labels/label.py
make eval-down
make eval-reset
```

The targets run on an internal Compose network (`cawasma-eval`, no internet
route, no published ports) with digest-pinned images, and are reached by
service name from containers on that network. `make eval` runs the full
evaluation (CAWASMA, ZAP, Nuclei; `harness/README.md`); CAWASMA reaches the
targets through the harness's TLS front with `ALLOWED_INTERNAL_HOSTS` set only
in `docker-compose.eval-scan.yml`.

The endpoint collector is a bounded, same-origin HTTP discovery tool for lab
data collection. It reads OpenAPI paths when available and then follows HTML
links up to a fixed page limit. It is not a replacement for CAWASMA's
HTTPS-only scanner.
