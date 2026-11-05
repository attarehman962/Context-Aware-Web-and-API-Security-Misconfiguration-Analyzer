"""Write docs/openapi.json and the example JSON in docs/examples/ (make openapi).

    python scripts/export_openapi.py           # write the files
    python scripts/export_openapi.py --check   # exit 1 if any file is out of date

openapi.json is what the frontend generates its client from; docs/examples/
holds one committed response per contract shape, taken from the same data as
MOCK_API mode (app/api/mock.py). CI and the test suite fail when either no
longer matches the code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.api import mock
from app.api.schemas.common import ErrorDetail, ErrorResponse, Page, PaginationMeta
from app.api.schemas.contract import ScanRequest, ScanStatus
from app.main import create_app

DOCS = Path(__file__).resolve().parents[2] / "docs"
OUTPUT = DOCS / "openapi.json"
EXAMPLES_DIR = DOCS / "examples"


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def render() -> str:
    return _json(create_app().openapi())


def render_examples() -> dict[str, str]:
    """One file per shape: request, each scan state, history, an error."""
    request = ScanRequest(url=mock.TARGET, authorisation_confirmed=True)
    history = Page[ScanStatus](
        items=mock.SCANS, meta=PaginationMeta(page=1, limit=20, total=len(mock.SCANS), pages=1)
    )
    error = ErrorResponse(
        error=ErrorDetail(code="INVALID_TARGET", message="Only HTTPS targets are allowed.")
    )
    files = {
        "scan-request.json": request,  # POST /api/scan body
        "scan-status-queued.json": mock.QUEUED_STATUS,  # POST /api/scan 202
        "results-done.json": mock.RESULTS[mock.DONE_ID],  # GET /api/results/{id}
        "results-running.json": mock.RESULTS[mock.RUNNING_ID],
        "results-failed.json": mock.RESULTS[mock.FAILED_ID],
        "scans.json": history,  # GET /api/scans
        "error.json": error,  # any 4xx/5xx
    }
    return {name: _json(model.model_dump(mode="json")) for name, model in files.items()}


def _outputs() -> dict[Path, str]:
    out = {OUTPUT: render()}
    out.update({EXAMPLES_DIR / name: text for name, text in render_examples().items()})
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="only verify the files are current")
    args = parser.parse_args(argv)
    outputs = _outputs()
    if args.check:
        stale = [
            p
            for p, text in outputs.items()
            if not p.exists() or p.read_text(encoding="utf-8") != text
        ]
        for path in stale:
            print(f"{path} is out of date: run `make openapi` and commit it.")
        if not stale:
            print(f"{OUTPUT} and {EXAMPLES_DIR}/ are up to date.")
        return 1 if stale else 0
    EXAMPLES_DIR.mkdir(exist_ok=True)
    for path, text in outputs.items():
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
