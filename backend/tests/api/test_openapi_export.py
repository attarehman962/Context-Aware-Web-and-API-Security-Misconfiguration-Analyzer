"""docs/openapi.json is the published contract: it must match the code."""

from __future__ import annotations

import json

from app.api.schemas import CONTRACT_VERSION
from scripts import export_openapi


def test_committed_openapi_matches_the_code():
    assert export_openapi.main(["--check"]) == 0, "run `make openapi` and commit docs/openapi.json"


def test_openapi_declares_the_contract():
    spec = json.loads(export_openapi.render())
    assert spec["info"]["x-contract-version"] == CONTRACT_VERSION
    for path in (
        "/api/scan",
        "/api/results/{scan_id}",
        "/api/results/{scan_id}/export",
        "/api/scans",
    ):
        assert path in spec["paths"], path
    assert "/api/scans/{scan_id}" not in spec["paths"]  # pre-contract routes removed
    assert not any(
        op.get("deprecated")
        for item in spec["paths"].values()
        for op in item.values()
        if isinstance(op, dict)
    )


def test_committed_example_json_matches_mock_mode():
    # Contract 3: an example response JSON committed for the frontend to consume.
    examples = export_openapi.render_examples()
    assert {"results-done.json", "scans.json", "scan-request.json"} <= set(examples)
    for name, content in examples.items():
        committed = export_openapi.EXAMPLES_DIR / name
        assert (
            committed.exists() and committed.read_text() == content
        ), f"docs/examples/{name} is stale: run `make openapi`"
