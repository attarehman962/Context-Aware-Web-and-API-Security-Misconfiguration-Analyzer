"""Eval tuning (Asim Prompt 10): the two dev-split false positives and their fixes."""
from __future__ import annotations

import json

import pytest

from app.core.contracts import EndpointInfo, ResponseInfo, SensitivityClass
from app.ml.body_classifier import detect
from app.ml.sensitivity import classify

# Assembled at run time so no JWT-shaped literal sits in the repo.
JWT = ("eyJ" + "0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYW1lMSJ9."
       "dGhpc2lzYXNpZ25hdHVyZWZvcnRlc3Rz")


def _resp(body: str) -> ResponseInfo:
    return ResponseInfo(url="https://t/openapi.json", status_code=200,
                        content_type="application/json", headers={}, body=body)


def test_openapi_examples_are_not_reported_as_leaked_data():
    spec = {"openapi": "3.0.1", "paths": {"/users/v1/login": {"post": {"responses": {"200": {
        "content": {"application/json": {"example": {"auth_token": JWT,
                                                     "email": "mail1@mail.com"}}}}}}}}}
    assert detect(_resp(json.dumps(spec))) == []


def test_a_real_secret_elsewhere_in_a_spec_is_still_found():
    spec = {"openapi": "3.0.1", "info": {"description": f"use token {JWT}"}, "paths": {}}
    assert [d.rule for d in detect(_resp(json.dumps(spec)))] == ["jwt"]


def test_example_keys_outside_api_docs_are_still_scanned():
    assert detect(_resp(json.dumps({"example": {"token": JWT}})))


@pytest.mark.parametrize("path, low", [
    ("/dvwa/css/login.css", True), ("/static/admin.js", True), ("/img/payment.PNG", True),
    ("/fonts/x.woff2?v=3", True), ("/login.php", False), ("/admin/users", False),
])
def test_static_assets_are_low_whatever_their_name(path, low):
    cls = classify(EndpointInfo(url="https://t" + path, path=path, method="GET"))
    if low:
        assert cls == SensitivityClass.LOW
    else:                       # not forced: whatever the built-in classifier says
        from app.core.contracts import builtin_classify
        assert cls == builtin_classify(EndpointInfo(url="https://t" + path, path=path,
                                                    method="GET"))
