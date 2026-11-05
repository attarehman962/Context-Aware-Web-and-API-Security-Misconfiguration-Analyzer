"""Tests for LLM-backed URL token expansion (provider call is mocked)."""

from __future__ import annotations

import pytest

from app.core.sensitivity import SensitivityClassifier
from app.db.models.enums import ContextClass
from app.services.llm import LLMClient

pytestmark = pytest.mark.asyncio

clf = SensitivityClassifier(use_embeddings=False)


async def test_expander_uses_llm_and_caches(monkeypatch):
    client = LLMClient(provider="anthropic", api_key="test-key")
    calls = {"n": 0}

    async def fake_query(tokens):
        calls["n"] += 1
        return {"usr": "user name", "iam": "identity access management"}

    monkeypatch.setattr(client, "_query", fake_query)

    out = await client.expand_abbreviations(["usr", "iam", "profile"])
    assert out["usr"] == "user name"
    assert out["iam"] == "identity access management"
    assert out["profile"] == "profile"  # left unchanged

    # Second call for the same tokens must hit the cache (no extra query).
    await client.expand_abbreviations(["usr", "iam"])
    assert calls["n"] == 1


async def test_classifier_uses_llm_expansions():
    # LLM expands 'usr' to a phrase containing 'user' -> HIGH via substring match.
    expansions = {"usr": "user name"}
    r = clf.classify("/xx/usr/profile", extra_expansions=expansions)
    assert r.context_class == ContextClass.HIGH


async def test_expander_falls_back_on_llm_error(monkeypatch):
    client = LLMClient(provider="openai", api_key="test-key")

    async def boom(tokens):
        raise RuntimeError("provider unreachable")

    monkeypatch.setattr(client, "_query", boom)
    out = await client.expand_abbreviations(["usr", "iam"])
    # Falls back to identity mapping; never raises.
    assert out == {"usr": "usr", "iam": "iam"}
    assert client.last_error is not None
