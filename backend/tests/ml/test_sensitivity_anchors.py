"""Anchor sensitivity classifier (Asim Prompt 6): contract, preprocessing, fallback,
determinism and speed. Tests that need the real model skip without the ML extras."""

from __future__ import annotations

import math
import time
from pathlib import Path

import pytest

from app.config import settings
from app.core.contracts import EndpointInfo, SensitivityClass
from app.ml import sensitivity
from app.ml.sensitivity import AnchorClassifier, load_config, path_text

ANCHORS = Path(settings.CONFIG_DIR) / "sensitivity_anchors.yaml"


def _ep(path: str, method: str = "GET") -> EndpointInfo:
    return EndpointInfo(url="https://shop.example.com" + path, path=path, method=method)


@pytest.fixture
def no_cache():
    sensitivity.anchor_classifier.cache_clear()
    yield
    sensitivity.anchor_classifier.cache_clear()


# ------------------------------------------------------------------ config


def test_the_committed_anchor_file_is_valid_and_off():
    config = load_config(ANCHORS)
    assert set(config.anchors) == set(SensitivityClass)
    assert all(len(phrases) >= 3 for phrases in config.anchors.values())
    # Off until the evaluation is re-run with it (the final tables used keywords).
    assert config.enabled is False


def test_an_anchor_file_missing_a_class_is_refused(tmp_path):
    bad = tmp_path / "anchors.yaml"
    bad.write_text("anchors:\n  LOW: [home]\n  HIGH: [login]\n")
    with pytest.raises(ValueError, match="every class"):
        load_config(bad)


# ----------------------------------------------------------- preprocessing


@pytest.mark.parametrize(
    "path, method, text",
    [
        ("/api/v1/userAccounts/42/pwd-reset", "GET", "GET api user accounts password reset"),
        ("/users/3f2b9c1e-8d4a-4b6e-9f1a-2c3d4e5f6a7b/orders", "post", "POST users orders"),
        ("/admin_panel/cfg.json", "GET", "GET administrator panel configuration json"),
        ("/users/:id", "DELETE", "DELETE users"),
        ("/", "GET", "GET home page"),
    ],
)
def test_paths_become_text(path, method, text):
    abbreviations = load_config(ANCHORS).abbreviations
    assert path_text(path, method, abbreviations) == text


# -------------------------------------------------- classifier, fake model


class FakeModel:
    """Embeds by keyword, so the scoring logic is tested without torch."""

    AXES = ("home", "profile", "login", "administrator")

    def encode(self, texts, normalize_embeddings=True):
        out = []
        for text in texts:
            v = [1.0 if a in text else 0.0 for a in self.AXES] + [0.1]
            norm = math.sqrt(sum(x * x for x in v))
            out.append([x / norm for x in v])
        return out


def _fake(threshold: float = 0.3) -> AnchorClassifier:
    config = load_config(ANCHORS)
    config = type(config)(
        **{
            **config.__dict__,
            "threshold": threshold,
            "anchors": {
                SensitivityClass.LOW: ("public home page",),
                SensitivityClass.MEDIUM: ("user profile",),
                SensitivityClass.HIGH: ("user login",),
                SensitivityClass.CRITICAL: ("administrator panel",),
            },
        }
    )
    return AnchorClassifier(config, model=FakeModel())


@pytest.mark.parametrize(
    "path, cls",
    [
        ("/", SensitivityClass.LOW),
        ("/me/profile", SensitivityClass.MEDIUM),
        ("/auth/login", SensitivityClass.HIGH),
        ("/admin/users", SensitivityClass.CRITICAL),
    ],
)
def test_best_anchor_wins(path, cls):
    assert _fake().classify(path) is cls


def test_below_the_threshold_the_default_class_is_used():
    assert _fake(threshold=0.99).classify("/shop/widgets") is SensitivityClass.MEDIUM


def test_classify_uses_the_keyword_classifier_while_anchors_are_off(no_cache, monkeypatch):
    called = []
    monkeypatch.setattr(
        sensitivity, "builtin_classify", lambda ep: called.append(ep.path) or SensitivityClass.HIGH
    )
    assert sensitivity.classify(_ep("/auth/login")) is SensitivityClass.HIGH
    assert called == ["/auth/login"]


def test_classify_never_raises(no_cache, monkeypatch):
    class Broken:
        def classify(self, path, method):
            raise RuntimeError("model crashed")

    monkeypatch.setattr(sensitivity, "anchor_classifier", lambda: Broken())
    assert isinstance(sensitivity.classify(_ep("/x")), SensitivityClass)
    assert sensitivity.classify(_ep("/site.css")) is SensitivityClass.LOW


# ------------------------------------------------------- real model (ML)


@pytest.fixture(scope="module")
def real():
    pytest.importorskip("sentence_transformers")
    try:
        return AnchorClassifier(load_config(ANCHORS))
    except Exception as exc:  # noqa: BLE001 - no model in the cache: skip, don't fail
        pytest.skip(f"model unavailable: {exc}")


def test_real_model_is_deterministic(real):
    paths = ["/api/v1/users/42", "/auth/login", "/admin/config", "/about"]
    assert [real.classify(p) for p in paths] == [real.classify(p) for p in paths]


def test_real_model_is_fast_enough_on_cpu(real):
    real.classify("/warm/up")
    paths = [f"/api/v1/section{i}/items" for i in range(20)]
    start = time.perf_counter()
    for p in paths:
        real.classify(p)
    per_path_ms = (time.perf_counter() - start) * 1000 / len(paths)
    assert per_path_ms < 50, f"{per_path_ms:.1f} ms per path"


def test_real_model_follows_the_labelling_guide_examples(real):
    assert real.classify("/") is SensitivityClass.LOW
    assert real.classify("/auth/login", "POST") is SensitivityClass.HIGH
    assert real.classify("/admin/users") is SensitivityClass.CRITICAL
