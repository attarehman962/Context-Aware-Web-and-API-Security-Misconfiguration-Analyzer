#!/usr/bin/env bash
# Starts what the full end-to-end test (e2e/eval-flow.spec.ts) scans against:
# the VAmPI evaluation target behind the eval TLS front, and CAWASMA (api +
# Celery worker) joined to the eval network, the way eval/harness/run_all.py
# does it. Run from the repository root; needs Docker and Python with the
# `cryptography` package.
#
#   bash frontend/scripts/eval-stack.sh          # start
#   bash frontend/scripts/eval-stack.sh down     # stop and remove
#
# Then: cd frontend && E2E_TARGET_URL=https://vampi-tls/ npm run test:e2e:real -- eval-flow
set -euo pipefail

EVAL=(docker compose -f docker-compose.eval.yml)
CAWASMA=(docker compose -f docker-compose.yml -f docker-compose.eval-scan.yml)

if [[ "${1:-}" == "down" ]]; then
  "${CAWASMA[@]}" down --volumes --remove-orphans
  "${EVAL[@]}" --profile scan down --volumes --remove-orphans
  exit 0
fi

# A CA and a certificate for every <target>-tls name, for this run only
# (eval/.run is git-ignored). Same helper as the harness's make_tls().
python - <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, "backend")
from scripts.demo_target import make_certificates

tls = Path("eval/.run/tls")
tls.mkdir(parents=True, exist_ok=True)
ca, cert, key = make_certificates(
    ["juice-shop-tls", "dvwa-tls", "vampi-tls", "crapi-tls"], [])
(tls / "ca.pem").write_bytes(ca)
(tls / "front.pem").write_bytes(cert + ca)
(tls / "front.key").write_bytes(key)
(tls / "front.key").chmod(0o644)  # read by nginx in its container
print("TLS: eval/.run/tls ready")
PY

# Only VAmPI: the TLS front resolves its upstreams per request, so the
# other targets need not run.
"${EVAL[@]}" up -d --wait vampi
"${EVAL[@]}" --profile scan up -d --wait --force-recreate tls-front
"${EVAL[@]}" exec -T vampi wget -qO- http://127.0.0.1:5000/createdb >/dev/null \
  && echo "VAmPI: database created"

"${CAWASMA[@]}" up -d --build --wait api worker
curl -fsS http://localhost:8000/health && echo
