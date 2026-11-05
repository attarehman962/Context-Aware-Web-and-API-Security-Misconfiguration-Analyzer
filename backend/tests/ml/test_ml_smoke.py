"""The ML stack installs and its models load (Asim's Prompt 1, item 5).

Skipped unless the ml extra is installed (pip install -e ".[ml]"); inside the
api image run `make ml-smoke`.
"""

from __future__ import annotations

import pytest

sentence_transformers = pytest.importorskip("sentence_transformers")
spacy = pytest.importorskip("spacy")


def test_minilm_and_spacy_load():
    vec = sentence_transformers.SentenceTransformer("all-MiniLM-L6-v2").encode("api login")
    doc = spacy.load("en_core_web_sm")("Reset the admin password")
    assert vec.shape == (384,) and [t.text for t in doc][:2] == ["Reset", "the"]
