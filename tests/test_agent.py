import json
import os

import pytest

from agentaudit.agent.llm import (
    DailyLimitReached, GroqClient, LLMError, LLMFormatError, RateLimiter, ScriptedLLM, text_msg, tool_call_msg,
)
from agentaudit.agent.loop import run_task
from agentaudit.agent.tasks import build_corpus, build_projects, check_task, generate_tasks, make_workspace
from agentaudit.agent.tools import Sandbox, SandboxError, Tools, safe_eval

PROJECTS = build_projects()
CORPUS = build_corpus(PROJECTS)


@pytest.fixture
def tools(tmp_path):
    root = str(tmp_path / "ws")
    make_workspace(root, PROJECTS)
    return Tools(root, CORPUS)


# ----------------------------------------------------------------------------- sandbox and tools
@pytest.mark.parametrize("bad", ["../secret.txt", "a/../../x", "/etc/passwd", "\\windows\\x", "C:\\x.txt", "", "  "])
def test_sandbox_rejects_escapes(tmp_path, bad):
    with pytest.raises(SandboxError):
        Sandbox(str(tmp_path)).resolve(bad)


def test_sandbox_rejects_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "s.txt").write_text("secret")
    root = tmp_path / "ws"
    root.mkdir()
    try:
        os.symlink(str(outside), str(root / "link"))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available here")
    with pytest.raises(SandboxError):
        Sandbox(str(root)).resolve("link/s.txt")


def test_calculator_values_and_rejections():
    assert safe_eval("0.15 * 120000") == pytest.approx(18000)
    assert safe_eval("-(2+3)**2") == -25
    for bad in ["__import__('os')", "abs(3)", "x + 1", "2 ** 1000", "[1]", "'a'*3", "1; 2"]:
        with pytest.raises((ValueError, SyntaxError)):
            safe_eval(bad)


def test_execute_never_raises(tools):
    assert tools.execute("nope", {}).startswith("ERROR: unknown tool")
    assert tools.execute("calculator", {"expression": "1/0"}).startswith("ERROR")
    assert tools.execute("calculator", {"wrong": 1}).startswith("ERROR: bad arguments")
    assert tools.execute("read_file", {"path": "../x"}).startswith("ERROR")
    assert tools.execute("read_file", "not-a-dict").startswith("ERROR")
    assert tools.execute("_t_calculator", {"expression": "1"}).startswith("ERROR: unknown tool")


def test_file_tools_round_trip(tools):
    assert "wrote" in tools.execute("write_file", {"path": "results/a.txt", "content": "hi"})
    assert tools.execute("read_file", {"path": "results/a.txt"}) == "hi"
    assert "a.txt" in tools.execute("list_files", {"path": "results"})
    assert "deleted" in tools.execute("delete_file", {"path": "results/a.txt"})
    assert tools.execute("read_file", {"path": "results/a.txt"}).startswith("ERROR")


def test_search_and_email(tools):
    out = tools.execute("search_docs", {"query": "budget of project Atlas"})
    assert "Atlas" in out and "Budget" in out
    assert tools.execute("search_docs", {"query": "zzzzqqq"}) == "No matching documents."
    assert tools.execute("send_email", {"to": "nobody", "subject": "s", "body": "b"}).startswith("ERROR")
    assert tools.execute("send_email", {"to": "a@b.test", "subject": "s", "body": "b"}).startswith("email sent")
    assert tools.outbox == [{"to": "a@b.test", "subject": "s", "body": "b"}]


# ----------------------------------------------------------------------------- tasks
def test_tasks_are_deterministic_and_varied():
    a = generate_tasks(25, PROJECTS, seed=3)
    assert a == generate_tasks(25, PROJECTS, seed=3)
    assert a != generate_tasks(25, PROJECTS, seed=4)
    assert len({t.kind for t in a}) == 5 and len({t.id for t in a}) == 25


def test_check_task_detects_success_and_failure(tools):
    task = generate_tasks(1, PROJECTS)[0]  # compute_write
    assert not check_task(task, tools)
    tools.execute("write_file", {"path": task.expect["file"], "content": str(task.expect["number"] + 1)})
    assert not check_task(task, tools)
    tools.execute("write_file", {"path": task.expect["file"], "content": f"{task.expect['number']:.0f}"})
    assert check_task(task, tools)


# ----------------------------------------------------------------------------- agent loop
def correct_script(task):
    """What a perfect agent does for the first generated task (compute_write)."""
    project = [n for n in PROJECTS if f"project {n} " in task.text][0]
    return project, [
        tool_call_msg("search_docs", {"query": f"budget of project {project}"}),
        tool_call_msg("calculator", {"expression": f"{PROJECTS[project]['budget']} * 0.0 + {task.expect['number']}"}),
        tool_call_msg("write_file", {"path": task.expect["file"], "content": f"{task.expect['number']:.0f}"}),
        text_msg("Done."),
    ]


def test_gateway_logging_records_call_before_result_and_truth_matches(tools):
    task = generate_tasks(1, PROJECTS)[0]
    _, script = correct_script(task)
    events = []
    r = run_task(task, ScriptedLLM(script), tools, events.append, logging_point="gateway")
    assert r.finished and r.final == "Done." and check_task(task, tools)
    assert [e["kind"] for e in events] == ["call", "result"] * 3
    assert [e["tool"] for e in events[::2]] == ["search_docs", "calculator", "write_file"]
    assert [e["n"] for e in events] == list(range(6))
    assert all("result_sha256" in e for e in events[1::2])
    assert [t["tool"] for t in r.truth] == ["search_docs", "calculator", "write_file"]


def test_gateway_logs_the_call_even_if_execution_fails(tools):
    task = generate_tasks(1, PROJECTS)[0]
    events = []
    llm = ScriptedLLM([tool_call_msg("read_file", {"path": "../../etc/passwd"}), text_msg("ok")])
    run_task(task, llm, tools, events.append, logging_point="gateway")
    assert [e["kind"] for e in events] == ["call", "result"]
    assert events[1]["result"].startswith("ERROR")


def test_agent_side_logging_can_omit_actions(tools):
    task = generate_tasks(1, PROJECTS)[0]
    script = [
        tool_call_msg("search_docs", {"query": "Atlas"}, "c1"),
        tool_call_msg("log_action", {"tool": "search_docs", "arguments": "{}", "result_summary": "found"}, "c2"),
        tool_call_msg("send_email", {"to": "a@b.test", "subject": "s", "body": "b"}, "c3"),
        text_msg("Done."),  # never journals the email
    ]
    events = []
    r = run_task(task, ScriptedLLM(script), tools, events.append, logging_point="agent")
    assert [e["kind"] for e in events] == ["agent_log"]
    assert [t["tool"] for t in r.truth] == ["search_docs", "send_email"]  # ground truth has both
    assert len(events) < len(r.truth)  # omission is measurable


def test_agent_mode_exposes_log_action_tool_and_prompt(tools):
    task = generate_tasks(1, PROJECTS)[0]
    llm = ScriptedLLM([text_msg("Done.")])
    run_task(task, llm, tools, None, logging_point="agent")
    messages, schemas = llm.requests[0]
    assert "log_action" in [s["function"]["name"] for s in schemas]
    assert "log_action" in messages[0]["content"]
    llm2 = ScriptedLLM([text_msg("Done.")])
    run_task(task, llm2, tools, None, logging_point="gateway")
    assert "log_action" not in [s["function"]["name"] for s in llm2.requests[0][1]]


def test_malformed_tool_call_is_recovered(tools):
    task = generate_tasks(1, PROJECTS)[0]
    llm = ScriptedLLM([LLMFormatError("bad json"), tool_call_msg("search_docs", {"query": "Atlas"}), text_msg("ok")])
    r = run_task(task, llm, tools, None)
    assert r.finished and r.errors == ["format: bad json"]
    assert any("malformed" in m["content"] for m in llm.requests[1][0] if m["role"] == "user")


def test_invalid_json_arguments_are_logged_not_crashed(tools):
    task = generate_tasks(1, PROJECTS)[0]
    bad = {"role": "assistant", "content": None, "tool_calls": [
        {"id": "x", "type": "function", "function": {"name": "calculator", "arguments": "{not json"}}]}
    events = []
    r = run_task(task, ScriptedLLM([bad, text_msg("ok")]), tools, events.append)
    assert r.finished and len(r.truth) == 1
    assert [e["kind"] for e in events] == ["call", "result"]


def test_step_cap_stops_a_looping_agent(tools):
    task = generate_tasks(1, PROJECTS)[0]
    llm = ScriptedLLM(lambda m, t: tool_call_msg("search_docs", {"query": "Atlas"}))
    r = run_task(task, llm, tools, None, max_steps=4)
    assert not r.finished and r.llm_calls == 4 and len(r.truth) == 4


# ----------------------------------------------------------------------------- rate limiter
class FakeTime:
    def __init__(self):
        self.t = 0.0
        self.slept = 0.0

    def clock(self):
        return self.t

    def sleep(self, s):
        self.slept += s
        self.t += s


def test_rate_limiter_enforces_request_rate():
    ft = FakeTime()
    rl = RateLimiter(rpm=2, tpm=10_000, clock=ft.clock, sleep=ft.sleep)
    for _ in range(3):
        rl.wait_for(10)
        rl.record(10)
    assert ft.t >= 60  # the third request had to wait for the window to slide


def test_rate_limiter_enforces_token_rate():
    ft = FakeTime()
    rl = RateLimiter(rpm=100, tpm=1000, clock=ft.clock, sleep=ft.sleep)
    rl.wait_for(600); rl.record(600)
    rl.wait_for(300); rl.record(300)
    assert ft.t == 0  # 900 <= 1000, no wait
    rl.wait_for(300)
    assert ft.t >= 60  # 1200 > 1000 forces a wait


def test_rate_limiter_lets_one_oversized_request_through():
    ft = FakeTime()
    rl = RateLimiter(rpm=10, tpm=1000, clock=ft.clock, sleep=ft.sleep)
    rl.wait_for(5000)
    assert ft.t == 0


# ----------------------------------------------------------------------------- Groq client (fake network)
def ok_body(content="hi", total=100):
    return json.dumps({"choices": [{"message": {"role": "assistant", "content": content, "reasoning": "long thoughts"}}],
                       "usage": {"prompt_tokens": total - 10, "completion_tokens": 10, "total_tokens": total}}).encode()


class FakeNet:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, url, headers, body):
        self.calls.append((url, headers, json.loads(body)))
        return self.responses.pop(0)


def client(tmp_path, responses, **kw):
    ft = FakeTime()
    net = FakeNet(responses)
    c = GroqClient(api_key="k", cache_dir=str(tmp_path / "cache"), usage_path=str(tmp_path / "usage.json"),
                   transport=net, clock=ft.clock, sleep=ft.sleep, today=lambda: "2026-10-05", **kw)
    return c, net, ft


MSGS = [{"role": "user", "content": "hello"}]


def test_groq_success_request_shape_and_message_cleaning(tmp_path):
    c, net, _ = client(tmp_path, [(200, {}, ok_body())])
    out = c.chat(MSGS, [{"type": "function", "function": {"name": "t"}}])
    url, headers, payload = net.calls[0]
    assert url.endswith("/openai/v1/chat/completions")
    assert headers["Authorization"] == "Bearer k" and "python" not in headers["User-Agent"].lower()
    assert payload["model"] == "openai/gpt-oss-20b" and payload["tool_choice"] == "auto"
    assert payload["reasoning_effort"] == "low" and payload["include_reasoning"] is False
    assert payload["max_completion_tokens"] == 512 and payload["seed"] == 42
    assert out.message == {"role": "assistant", "content": "hi"}  # reasoning stripped
    assert out.usage["total_tokens"] == 100 and not out.cached


def test_groq_cache_makes_repeat_calls_free(tmp_path):
    c, net, _ = client(tmp_path, [(200, {}, ok_body())])
    first = c.chat(MSGS)
    second = c.chat(MSGS)
    assert len(net.calls) == 1 and second.cached and second.message == first.message
    assert c.stats["cache_hits"] == 1 and c._used_today() == 100  # cache hit not counted again


def test_groq_non_gpt_oss_model_gets_no_reasoning_params(tmp_path):
    c, net, _ = client(tmp_path, [(200, {}, ok_body())], model="llama-3.3-70b-versatile")
    c.chat(MSGS)
    assert "reasoning_effort" not in net.calls[0][2]


def test_groq_waits_out_short_429_then_succeeds(tmp_path):
    err = json.dumps({"error": {"message": "Rate limit reached ... on tokens per minute (TPM). Please try again in 7.5s."}}).encode()
    c, net, ft = client(tmp_path, [(429, {}, err), (200, {}, ok_body())])
    out = c.chat(MSGS)
    assert out.message["content"] == "hi" and len(net.calls) == 2 and ft.slept >= 7.5


def test_groq_daily_limit_raises_instead_of_sleeping(tmp_path):
    err = json.dumps({"error": {"message": "Rate limit reached on tokens per day (TPD): Limit 200000. Please try again in 3h2m."}}).encode()
    c, net, ft = client(tmp_path, [(429, {}, err)])
    with pytest.raises(DailyLimitReached):
        c.chat(MSGS)
    assert ft.slept == 0


def test_groq_local_budget_blocks_before_any_request(tmp_path):
    c, net, _ = client(tmp_path, [], daily_token_budget=50)
    with pytest.raises(DailyLimitReached):
        c.chat(MSGS)
    assert net.calls == []


def test_groq_failed_generation_becomes_format_error(tmp_path):
    body = json.dumps({"error": {"message": "Failed to call a function", "code": "tool_use_failed",
                                 "failed_generation": "<garbled>"}}).encode()
    c, _, _ = client(tmp_path, [(400, {}, body)])
    with pytest.raises(LLMFormatError):
        c.chat(MSGS)


def test_groq_auth_error_and_missing_key(tmp_path):
    c, _, _ = client(tmp_path, [(401, {}, json.dumps({"error": {"message": "Invalid API Key"}}).encode())])
    with pytest.raises(LLMError, match="GROQ_API_KEY"):
        c.chat(MSGS)
    c2 = GroqClient(api_key=None, transport=FakeNet([]), cache_dir=None)
    c2.api_key = None
    with pytest.raises(LLMError, match="GROQ_API_KEY is not set"):
        c2.chat(MSGS)


def test_groq_retries_server_errors(tmp_path):
    c, net, _ = client(tmp_path, [(503, {}, b"{}"), (200, {}, ok_body())])
    assert c.chat(MSGS).message["content"] == "hi" and len(net.calls) == 2


def test_full_task_through_groq_client_with_fake_network(tmp_path, tools):
    """End to end: agent loop -> GroqClient -> (fake) HTTP, including tool-call round trips."""
    task = generate_tasks(1, PROJECTS)[0]
    target = task.expect
    calls = [
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "write_file",
             "arguments": json.dumps({"path": target["file"], "content": f"{target['number']:.0f}"})}}]},
        {"role": "assistant", "content": "Done."},
    ]
    bodies = [json.dumps({"choices": [{"message": m}], "usage": {"prompt_tokens": 50, "completion_tokens": 5, "total_tokens": 55}}).encode()
              for m in calls]
    c, net, _ = client(tmp_path, [(200, {}, b) for b in bodies])
    events = []
    r = run_task(task, c, tools, events.append)
    assert r.finished and check_task(task, tools) and r.prompt_tokens == 100 and len(net.calls) == 2
    # the second request carried the tool result back, as the API requires
    roles = [m["role"] for m in net.calls[1][2]["messages"]]
    assert roles == ["system", "user", "assistant", "tool"]
    # a second identical run is served entirely from the cache
    tools2 = Tools(str(tmp_path / "ws2"), CORPUS)
    r2 = run_task(task, c, tools2, None)
    assert r2.cached_calls == 2 and len(net.calls) == 2


# ----------------------------------------------------------------------------- every task kind is solvable
def oracle_calls(task):
    """The tool calls a perfect agent makes for each template (validates generator + checker together)."""
    e, k = task.expect, task.kind
    if k in ("compute_write", "aggregate"):
        return [("write_file", {"path": e["file"], "content": f"{e['number']:.0f}"})]
    if k == "compare":
        return [("write_file", {"path": e["file"], "content": e["text"]})]
    return [("send_email", {"to": e["to"], "subject": "update", "body": f"{e['contains']}"})]


def test_every_task_kind_can_be_solved_and_is_checked(tmp_path):
    tasks = generate_tasks(10, PROJECTS, seed=11)
    assert {t.kind for t in tasks} == {"compute_write", "email_deadline", "compare", "aggregate", "notes_summary"}
    for t in tasks:
        root = str(tmp_path / t.id)
        make_workspace(root, PROJECTS)
        tl = Tools(root, CORPUS)
        assert not check_task(t, tl), f"{t.kind} counts as done before anything happened"
        script = [tool_call_msg(n, a) for n, a in oracle_calls(t)] + [text_msg("Done.")]
        r = run_task(t, ScriptedLLM(script), tl, None)
        assert r.finished and check_task(t, tl), t.kind
