import csv
import os

import pytest

from agentaudit.agent.llm import DailyLimitReached
from agentaudit.agent.oracle import OracleLLM
from agentaudit.agent.tasks import build_corpus, build_projects, generate_tasks
from agentaudit.experiment.evaluate import evaluate, make_specs
from agentaudit.experiment.record import load_stream, load_tasks, load_truth, read_jsonl, record_stream
from agentaudit.experiment.report import ROWS, make_report, rate, read_csv


class LimitedOracle(OracleLLM):
    """Raises DailyLimitReached after `budget` model calls, like an exhausted free tier."""

    def __init__(self, tasks, budget):
        super().__init__(tasks)
        self.budget = budget

    def chat(self, messages, tools=None):
        if self.budget <= 0:
            raise DailyLimitReached("test limit")
        self.budget -= 1
        return super().chat(messages, tools)


@pytest.fixture
def world():
    projects = build_projects()
    return projects, build_corpus(projects), generate_tasks(10, projects)


def test_record_resume_and_orphan_cleanup(tmp_path, world):
    projects, corpus, tasks = world
    out = str(tmp_path / "rec")
    r1 = record_stream(LimitedOracle(tasks, 8), tasks, projects, corpus, out)
    assert r1["status"] == "daily_limit" and 0 < r1["done"] < 10
    # simulate a crash in the middle of writing the next task: stream rows without a completion marker
    with open(os.path.join(out, "stream.jsonl"), "a") as f:
        f.write('{"run": "t009", "kind": "call"}\n{"torn')
    r2 = record_stream(OracleLLM(tasks), tasks, projects, corpus, out)
    assert r2["status"] == "complete" and r2["done"] == 10
    stream, truth, rows = load_stream(out), load_truth(out), load_tasks(out)
    assert len(rows) == 10 and len({r["id"] for r in rows}) == 10
    assert sum(r["n_events"] for r in rows) == len(stream) == 2 * len(truth)
    assert all(r["success"] for r in rows)
    with pytest.raises(ValueError):
        record_stream(OracleLLM(tasks), tasks, projects, corpus, out, logging_point="agent")


def test_agent_logging_point_records_journal(tmp_path, world):
    projects, corpus, tasks = world
    out = str(tmp_path / "ag")
    record_stream(OracleLLM(tasks), tasks, projects, corpus, out, logging_point="agent")
    stream, truth = load_stream(out), load_truth(out)
    assert {e["kind"] for e in stream} == {"agent_log"} and len(stream) == len(truth)


def test_specs_geometry():
    for N, k in [(96, 7), (96, 40), (10, 50), (30, 10)]:
        L = (N // k) * k
        for s in make_specs(N, L):
            if s["op"] == "truncate":
                assert s["region"] == ("past_anchor" if s["pos"] < L else "within_window")
            else:
                assert s["region"] == ("history" if s["pos"] < L else "tail")
                assert 0 <= s["pos"] < N


def test_evaluation_matrix(tmp_path, world):
    projects, corpus, tasks = world
    rec = str(tmp_path / "rec")
    record_stream(OracleLLM(tasks), tasks, projects, corpus, rec)
    res = str(tmp_path / "res")
    meta = evaluate(rec, res, ks=[7, 1000], progress=lambda m: None)
    det = read_csv(os.path.join(res, "detection.csv"))
    present = [m for m in ["M0", "M1", "M2", "M3", "M4"] if m not in meta["skipped"]]
    assert {"M0", "M1", "M3"} <= set(present)
    assert meta["coverage"] == 1.0

    def r(rows, m, pred):
        h, t = rate(rows, m, pred)
        assert t > 0
        return h / t

    for k in (7, 1000):
        rows = [x for x in det if x["k"] == k]
        for m in present:
            assert r(rows, m, lambda x: x["attacker"] == "none") == 0, "false alarm on an untouched log"
            assert r(rows, m, lambda x: x["attacker"] == "A3b") == 0, "omission must be invisible"
        assert r(rows, "M0", lambda x: x["attacker"] != "none") == 0
        for op in ("edit", "delete", "reorder", "insert"):
            for m in present[1:]:
                assert r(rows, m, lambda x: x["attacker"] == "A1" and x["op"] == op) == 1
        assert r(rows, "M1", lambda x: x["attacker"] == "A2") == 0
        assert r(rows, "M1", lambda x: x["op"] == "truncate") == 0
    rows7 = [x for x in det if x["k"] == 7]
    for m in present[2:]:
        assert r(rows7, m, lambda x: x["attacker"] == "A2" and x["region"] == "tail") == 0
        assert r(rows7, m, lambda x: x["attacker"] == "A2" and x["region"] == "history") == 1
        assert r(rows7, m, lambda x: x["op"] == "truncate" and x["region"] == "within_window") == 0
        assert r(rows7, m, lambda x: x["op"] == "truncate" and x["region"] == "past_anchor") == 1
    rows_big = [x for x in det if x["k"] == 1000]  # no anchor ever published: window is the whole log
    for m in present[2:]:
        assert r(rows_big, m, lambda x: x["attacker"] == "A2") == 0
        assert r(rows_big, m, lambda x: x["op"] == "truncate") == 0
    text = make_report(res, report_k=7)
    assert "Detection rate" in text and os.path.exists(os.path.join(res, "tables.tex"))
    assert len(ROWS) == 8
    with open(os.path.join(res, "cost.csv")) as f:
        assert len(list(csv.DictReader(f))) == 2 * len(present)

