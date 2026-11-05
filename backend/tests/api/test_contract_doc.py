"""Every example in docs/api-contract.md must validate against the contract.

Examples are marked ``<!-- example: ModelName -->`` directly above a ```json block.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.api.schemas import CONTRACT_VERSION, ScanRequest, ScanResults, ScanStatus
from app.api.schemas.common import ErrorResponse, Page

DOC = Path(__file__).resolve().parents[3] / "docs" / "api-contract.md"
MODELS = {
    "ScanRequest": ScanRequest,
    "ScanStatus": ScanStatus,
    "ScanResults": ScanResults,
    "ScanList": Page[ScanStatus],
    "ErrorResponse": ErrorResponse,
}
EXAMPLES = re.findall(r"<!-- example: (\w+) -->\s*```json\n(.*?)```", DOC.read_text(), re.S)


def test_doc_has_an_example_for_every_contract_shape():
    assert {name for name, _ in EXAMPLES} == set(MODELS)


@pytest.mark.parametrize("name, body", EXAMPLES, ids=[n for n, _ in EXAMPLES])
def test_doc_example_is_valid(name, body):
    model = MODELS[name]
    model.model_validate(json.loads(body))


def test_doc_states_the_current_version():
    assert DOC.read_text().startswith(f"# CAWASMA API contract v{CONTRACT_VERSION}")
