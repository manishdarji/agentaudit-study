"""Record the agent's action stream once; every mechanism is later evaluated on the SAME stream.

Files in out_dir (all JSON Lines):
  stream.jsonl  events that reached the audit sink (what a log would contain)
  truth.jsonl   every tool call that really happened (never sent to the sink)
  tasks.jsonl   one row per finished task; written LAST, so it is the completion marker

The run can be stopped at any time (Groq daily limit, Ctrl-C, crash) and resumed: finished tasks are
skipped and rows of a half-finished task are dropped.
"""
import json
import os
import time

from ..agent.llm import DailyLimitReached, LLMError
from ..agent.loop import run_task
from ..agent.tasks import check_task, make_workspace
from ..agent.tools import Tools


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    break  # torn last line after a crash: ignore it and everything after
    return rows


def _write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def _append_jsonl(path, rows):
    with open(path, "a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def load_stream(d):
    return read_jsonl(os.path.join(d, "stream.jsonl"))


def load_truth(d):
    return read_jsonl(os.path.join(d, "truth.jsonl"))


def load_tasks(d):
    return read_jsonl(os.path.join(d, "tasks.jsonl"))


def record_stream(llm, tasks, projects, corpus, out_dir, logging_point="gateway",
                  max_steps=10, progress=None, clock=time.time, model="unknown", extra_instruction=None,
                  condition=None):
    os.makedirs(out_dir, exist_ok=True)
    meta_path = os.path.join(out_dir, "record_meta.json")
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            old = json.load(f)
        if old.get("logging_point") != logging_point:
            raise ValueError(f"{out_dir} was recorded with logging_point={old.get('logging_point')!r}; "
                             f"use a different --out directory for {logging_point!r}")
    else:
        with open(meta_path, "w") as f:
            json.dump({"logging_point": logging_point, "model": model, "condition": condition,
                       "extra_instruction": extra_instruction}, f)

    ws = os.path.join(out_dir, "workspace")
    if not os.path.isdir(ws):
        make_workspace(ws, projects)

    paths = {n: os.path.join(out_dir, n + ".jsonl") for n in ("stream", "truth", "tasks")}
    done = {r["id"] for r in read_jsonl(paths["tasks"])}
    for name in ("stream", "truth"):  # drop rows of a task that never reached its completion marker
        rows = read_jsonl(paths[name])
        keep = [r for r in rows if r.get("run") in done]
        if len(keep) != len(rows):
            _write_jsonl(paths[name], keep)

    status, new = "complete", 0
    for t in tasks:
        if t.id in done:
            continue
        tools = Tools(ws, corpus)
        events = []
        try:
            r = run_task(t, llm, tools, events.append, logging_point=logging_point,
                         max_steps=max_steps, clock=clock, extra_instruction=extra_instruction)
        except DailyLimitReached:
            status = "daily_limit"
            break
        except LLMError as e:
            status = f"llm_error: {e}"
            break
        truth = [dict(x, run=t.id) for x in r.truth]
        _append_jsonl(paths["stream"], events)
        _append_jsonl(paths["truth"], truth)
        _append_jsonl(paths["tasks"], [{
            "id": t.id, "kind": t.kind, "finished": r.finished, "success": bool(check_task(t, tools)),
            "steps": r.steps, "llm_calls": r.llm_calls, "cached_calls": r.cached_calls,
            "prompt_tokens": r.prompt_tokens, "completion_tokens": r.completion_tokens,
            "errors": r.errors, "n_events": len(events), "n_truth": len(truth)}])
        done.add(t.id)
        new += 1
        if progress:
            progress(t, r, len(done), len(tasks))
    return {"status": status, "done": len(done), "total": len(tasks), "new": new}
