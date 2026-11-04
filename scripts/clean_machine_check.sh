#!/usr/bin/env bash
# Clean-machine check: does CAWASMA come up and scan from a fresh clone, with
# nothing from this machine? Neelam (or CI) runs it to confirm the stack is
# reproducible.
#
#   scripts/clean_machine_check.sh                 # this repo's origin, current branch
#   REPO=https://github.com/... REF=main scripts/clean_machine_check.sh
#   FAST=1 scripts/clean_machine_check.sh          # reuse the Docker build cache
#   KEEP=1 scripts/clean_machine_check.sh          # leave the stack and clone running
#
# Steps: fresh clone -> docker compose build (--pull --no-cache unless FAST=1)
# -> up (api, worker, postgres, redis, demo HTTPS target) -> migrate (check at
# head) -> seed -> demo scan through POST /api/scan on the Celery worker ->
# verify results (scripts/verify_scan.py: ranking, recomputable CVSS vectors,
# every export format, SSE) -> tear down.
#
# Needs only git, docker (with compose v2) and curl. It runs as its own compose
# project on its own ports and image tag, so a developer's stack is untouched.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${REPO:-$(git -C "$here" remote get-url origin)}"
REF="${REF:-$(git -C "$here" rev-parse --abbrev-ref HEAD)}"
PROJECT="${PROJECT:-cawasma-clean}"
export CAWASMA_IMAGE_TAG="${CAWASMA_IMAGE_TAG:-clean}"
export API_HOST_PORT="${API_HOST_PORT:-18000}"
export POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-15446}"
export REDIS_HOST_PORT="${REDIS_HOST_PORT:-16379}"
API="http://localhost:${API_HOST_PORT}"
TARGET="https://demo-target:8443/"

current_step="setup"
step() { current_step="$*"; printf '\n==> %s\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

for tool in git docker curl; do
    command -v "$tool" >/dev/null || fail "$tool is not installed"
done
docker compose version >/dev/null 2>&1 || fail "docker compose v2 is required"

work="$(mktemp -d "${TMPDIR:-/tmp}/cawasma-clean.XXXXXX")"
compose() {
    docker compose -p "$PROJECT" --project-directory "$work/repo" \
        -f "$work/repo/docker-compose.yml" -f "$work/repo/docker-compose.demo.yml" "$@"
}
cleanup() {
    status=$?
    if [ "${KEEP:-0}" = "1" ]; then
        printf '\nKEEP=1: stack "%s" on %s, clone in %s\n' "$PROJECT" "$API" "$work"
    else
        compose down --volumes --remove-orphans >/dev/null 2>&1 || true
        rm -rf "$work"
    fi
    if [ "$status" -ne 0 ]; then
        printf '\nclean-machine check FAILED at step "%s" (exit %s)\n' \
            "$current_step" "$status" >&2
    fi
}
trap cleanup EXIT

step "fresh clone of $REPO ($REF)"
git clone --quiet --depth 1 --branch "$REF" "$REPO" "$work/repo"
git -C "$work/repo" log -1 --format='    %h %s'
[ -e "$work/repo/.env" ] && fail "the clone has a .env: it must not be committed"

step "build images (no .env, defaults only)"
# The image is about 4 GB; a full disk shows up only as "failed to extract layer".
# With the containerd image store, layers are unpacked under /var/lib/containerd.
for dir in "$(docker info -f '{{.DockerRootDir}}')" /var/lib/containerd; do
    [ -d "$dir" ] || continue
    free_gb="$(df -Pk "$dir" | awk 'NR==2 {print int($4/1048576)}')"
    [ "$free_gb" -ge 8 ] || echo "    warning: $free_gb GB free under $dir; the build needs about 8"
done
if [ "${FAST:-0}" = "1" ]; then compose build; else compose build --pull --no-cache; fi

step "start the stack and wait for every healthcheck"
compose up -d --wait || { compose ps; compose logs --tail=60; fail "stack did not become healthy"; }
curl -fsS "$API/health" >/dev/null || fail "api /health"

step "migrate: database at the latest Alembic revision"
compose exec -T api alembic upgrade head
current="$(compose exec -T api alembic current 2>/dev/null | awk '{print $1}' | tail -1)"
head="$(compose exec -T api alembic heads 2>/dev/null | awk '{print $1}' | tail -1)"
[ -n "$head" ] && [ "$current" = "$head" ] || fail "alembic current ($current) != head ($head)"
echo "    at $head"

step "seed sample data"
compose exec -T api python -m scripts.seed
seeded="$(curl -fsS "$API/api/scans?limit=100" | grep -o '"scan_id"' | wc -l)"
[ "$seeded" -ge 2 ] || fail "seed: expected at least 2 scans, got $seeded"

step "demo scan of $TARGET (queued on the Celery worker)"
body="{\"url\": \"$TARGET\", \"authorisation_confirmed\": true}"
created="$(curl -fsS -X POST "$API/api/scan" -H 'content-type: application/json' -d "$body")"
scan_id="$(printf '%s' "$created" | sed -n 's/.*"scan_id": *"\([0-9a-f-]*\)".*/\1/p')"
[ -n "$scan_id" ] || fail "POST /api/scan: $created"
echo "    scan $scan_id"
for _ in $(seq 1 150); do
    status="$(curl -fsS "$API/api/results/$scan_id" | sed -n 's/.*"status": *"\([A-Z]*\)".*/\1/p' | head -1)"
    case "$status" in DONE|FAILED) break ;; esac
    sleep 2
done
echo "    status $status"
[ "$status" = "DONE" ] || { compose logs --tail=80 worker; fail "demo scan ended $status"; }
compose logs worker 2>&1 | grep -q "$scan_id" || fail "the worker did not run the scan"

step "verify results"
compose exec -T api python -m scripts.verify_scan --api http://localhost:8000 \
    --expect HDR-001 -- "$scan_id"

printf '\nclean-machine check PASSED (%s @ %s)\n' "$REPO" "$(git -C "$work/repo" rev-parse --short HEAD)"
