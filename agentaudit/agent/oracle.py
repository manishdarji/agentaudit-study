"""A perfect rule-based agent: solves every task template with no network and no tokens.

Use it for free dry runs of the whole pipeline and in tests. It is NOT a model: a real agent makes
mistakes, takes extra steps and may forget to journal, which is exactly what the live runs measure.
"""
import json
import re

from .llm import LLMResult, text_msg, tool_call_msg

_ZERO = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def intended_calls(task) -> list:
    e, kind = task.expect, task.kind
    if kind == "notes_summary":
        m = re.search(r"notes/[a-z0-9_]+\.txt", task.text)
        first = ("read_file", {"path": m.group(0) if m else "notes/atlas.txt"})
    else:
        first = ("search_docs", {"query": " ".join(task.text.split()[:8])})
    if kind in ("compute_write", "aggregate"):
        rest = [("calculator", {"expression": str(e["number"])}),
                ("write_file", {"path": e["file"], "content": f"{e['number']:.0f}"})]
    elif kind == "compare":
        rest = [("write_file", {"path": e["file"], "content": e["text"]})]
    else:
        rest = [("send_email", {"to": e["to"], "subject": "Update", "body": e["contains"]})]
    return [first] + rest


class OracleLLM:
    def __init__(self, tasks):
        self.tasks = list(tasks)

    def chat(self, messages, tools=None) -> LLMResult:
        user = next(m["content"] for m in messages if m["role"] == "user")
        task = next(t for t in self.tasks if user.startswith(t.text))
        journal = any(s["function"]["name"] == "log_action" for s in (tools or []))
        seq = []
        for name, args in intended_calls(task):
            seq.append((name, args))
            if journal:
                seq.append(("log_action", {"tool": name, "arguments": json.dumps(args), "result_summary": "ok"}))
        done = sum(1 for m in messages if m["role"] == "assistant" and m.get("tool_calls"))
        if done < len(seq):
            name, args = seq[done]
            return LLMResult(tool_call_msg(name, args, f"call_{done}"), dict(_ZERO))
        return LLMResult(text_msg("Done."), dict(_ZERO))

