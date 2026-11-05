"""docker-compose.eval.yml wiring (review asim-p04 #3).

Docker does not publish ports for containers whose only network is internal,
so the targets are reached from a collector service inside the network.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from tests.eval.conftest import load_eval_script

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.eval.yml").read_text())
SERVICES = COMPOSE["services"]


def test_network_is_internal_and_no_service_publishes_dead_ports():
    assert COMPOSE["networks"]["eval"]["internal"] is True
    assert [name for name, svc in SERVICES.items() if svc.get("ports")] == []


def test_collector_runs_inside_the_eval_network():
    collector = SERVICES["collector"]
    assert collector["networks"] == ["eval"]
    assert "@sha256:" in collector["image"]  # pinned like the targets
    assert "collect_endpoints.py" in " ".join(collector["command"])


def test_collector_defaults_point_at_compose_services():
    targets = load_eval_script("labels/collect_endpoints.py").TARGETS
    for name, url in targets.items():
        assert urlparse(url).hostname in SERVICES, f"{name}: {url} is not an eval service"


def test_targets_do_not_carry_cawasma_settings():
    # ALLOWED_INTERNAL_HOSTS is a CAWASMA (scanner) setting; the targets ignore it.
    offenders = [
        name
        for name, svc in SERVICES.items()
        if "ALLOWED_INTERNAL_HOSTS" in (svc.get("environment") or {})
    ]
    assert offenders == []
