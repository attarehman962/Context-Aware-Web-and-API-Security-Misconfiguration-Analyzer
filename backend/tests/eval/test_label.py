"""eval/labels/label.py (review asim-p04 #21)."""
from __future__ import annotations

import csv

import pytest

from tests.eval.conftest import load_eval_script

ROWS = [("vampi", "GET", "/users/v1"), ("vampi", "POST", "/users/v1/login"),
        ("vampi", "GET", "/books/v1")]


@pytest.fixture
def labeller(tmp_path, monkeypatch):
    module = load_eval_script("labels/label.py")
    raw = tmp_path / "raw.csv"
    with raw.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["target", "method", "path"])
        writer.writerows(ROWS)
    monkeypatch.setattr(module, "INPUT", raw)
    monkeypatch.setattr(module, "OUTPUT", tmp_path / "labelled.csv")
    return module


def _feed(monkeypatch, *answers):
    queue = list(answers)

    def fake_input(prompt=""):
        if not queue:
            raise EOFError
        answer = queue.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr("builtins.input", fake_input)


def _labels(module):
    with module.OUTPUT.open(newline="") as handle:
        return {(r["method"], r["path"]): r["sensitivity_class"] for r in csv.DictReader(handle)}


def _rows_of(path):
    with path.open(newline="") as handle:
        return {(r["method"], r["path"]): r for r in csv.DictReader(handle)}


def test_invalid_key_reprompts_the_same_endpoint(labeller, monkeypatch):
    _feed(monkeypatch, "9", "2", "q")   # typo, then MEDIUM, quit
    assert labeller.main(["--labeler", "asim"]) == 0
    assert _labels(labeller) == {("GET", "/users/v1"): "MEDIUM"}


@pytest.mark.parametrize("interrupt", [EOFError(), KeyboardInterrupt()])
def test_ctrl_d_or_ctrl_c_saves_and_exits_cleanly(labeller, monkeypatch, interrupt):
    _feed(monkeypatch, "3", interrupt)
    assert labeller.main(["--labeler", "asim"]) == 0
    assert _labels(labeller) == {("GET", "/users/v1"): "HIGH"}


def test_resume_skips_already_labelled_rows(labeller, monkeypatch):
    _feed(monkeypatch, "1", "q")
    labeller.main(["--labeler", "asim"])
    _feed(monkeypatch, "4", "q")   # next run starts at the second row
    labeller.main(["--labeler", "asim"])
    assert _labels(labeller) == {("GET", "/users/v1"): "LOW",
                                 ("POST", "/users/v1/login"): "CRITICAL"}


def test_name_is_asked_once_and_a_note_can_follow_the_key(labeller, monkeypatch):
    _feed(monkeypatch, "asim", "2 user list", "3", "q")
    labeller.main([])
    rows = _rows_of(labeller.OUTPUT)
    assert rows[("GET", "/users/v1")]["notes"] == "user list"
    assert {r["labeler"] for r in rows.values()} == {"asim"}


def test_second_labeller_gets_the_same_sample_in_their_own_file(labeller, monkeypatch,
                                                                tmp_path):
    _feed(monkeypatch, "1", "1", "q")
    labeller.main(["--labeler", "asim", "--sample", "2"])
    other = tmp_path / "neelam.csv"
    _feed(monkeypatch, "2", "2", "q")
    labeller.main(["--labeler", "neelam", "--sample", "2", "--output", str(other)])
    assert set(_rows_of(other)) == set(_rows_of(labeller.OUTPUT))   # same paths
    assert {r["sensitivity_class"] for r in _rows_of(labeller.OUTPUT).values()} == {"LOW"}
