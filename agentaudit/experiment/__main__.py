"""Command line:  python -m agentaudit.experiment {record|evaluate|report|dry-run} ...

record     run the agent on N tasks and save its action stream (resumable; uses the Groq free tier)
evaluate   replay a recorded stream into M0-M4, attack, verify, measure cost
report     write results.md and tables.tex from an evaluation
dry-run    record with the rule-based OracleLLM (no network, no tokens), evaluate and report
"""
import argparse
import os
import sys

from ..agent.tasks import build_corpus, build_projects, generate_tasks
from .evaluate import evaluate
from .record import record_stream
from .report import make_report


def _opts(a):
    return {"tsa_url": a.tsa_url, "tsa_ca": a.tsa_ca, "tsa_untrusted": a.tsa_untrusted,
            "rpc_url": a.rpc_url, "contract": a.contract}


def _record(a, offline):
    projects = build_projects()
    corpus = build_corpus(projects)
    tasks = generate_tasks(a.tasks, projects, seed=a.task_seed)
    if offline:
        from ..agent.oracle import OracleLLM
        llm, model = OracleLLM(tasks), "oracle (rule-based, offline)"
    else:
        from ..agent.llm import GroqClient
        llm = GroqClient(cache_dir=os.path.join(a.out, "cache"), usage_path=os.path.join(a.out, "usage.json"))
        model = llm.model
    print(f"recording {len(tasks)} tasks, logging point {a.logging_point}, model {model}")

    def prog(t, r, done, total):
        print(f"  [{done}/{total}] {t.id} {t.kind}: events={len(r.truth)} finished={r.finished} tokens="
              f"{r.prompt_tokens + r.completion_tokens}")

    res = record_stream(llm, tasks, projects, corpus, a.out, a.logging_point, progress=prog, model=model)
    print(res)
    if res["status"] == "daily_limit":
        print("Daily limit reached. Run the same command again tomorrow; finished tasks are kept.")
    return res


def _attack_record(a):
    from ..agent.attackers import ScriptedAttackerLLM
    from .attack_record import record_attacks
    from .record import load_stream
    projects = build_projects()
    corpus = build_corpus(projects)
    tasks = generate_tasks(a.tasks, projects, seed=a.task_seed + 100)
    benign = load_stream(a.benign)
    if a.offline:
        llm, model = ScriptedAttackerLLM(tasks, a.scenario, a.mode), f"scripted attacker ({a.mode or 'default'})"
    else:
        from ..agent.llm import GroqClient
        llm = GroqClient(cache_dir=os.path.join(a.out, "cache"), usage_path=os.path.join(a.out, "usage.json"))
        model = llm.model
    lp = a.logging_point or ("gateway" if a.scenario == "A3a" else "agent")
    print(f"recording {len(tasks)} {a.scenario} runs, logging point {lp}, model {model}")

    def prog(t, row, done, total):
        print(f"  [{done}/{total}] {t.id} exfil={row['exfil_done']} tampered={row['attempted_cover']} "
              f"journaled_exfil={row['exfil_journaled']} tokens={row['tokens']}")

    res = record_attacks(llm, tasks, projects, corpus, a.out, a.scenario, lp, benign, progress=prog, model=model)
    print(res)
    if res["status"] == "daily_limit":
        print("Daily limit reached. Run the same command again tomorrow; finished runs are kept.")


def main(argv=None):
    try:  # optional: read GROQ_API_KEY etc. from a .env file
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    p = argparse.ArgumentParser(prog="agentaudit.experiment")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_rec(sp):
        sp.add_argument("--out", required=True)
        sp.add_argument("--tasks", type=int, default=100)
        sp.add_argument("--task-seed", type=int, default=1)
        sp.add_argument("--logging-point", choices=["gateway", "agent"], default="gateway")

    def add_eval(sp):
        sp.add_argument("--k", type=int, nargs="+", default=[10, 50, 100, 500])
        sp.add_argument("--report-k", type=int)
        sp.add_argument("--tsa-url"); sp.add_argument("--tsa-ca"); sp.add_argument("--tsa-untrusted")
        sp.add_argument("--rpc-url"); sp.add_argument("--contract")

    r = sub.add_parser("record"); add_rec(r)
    r.add_argument("--offline", action="store_true")
    e = sub.add_parser("evaluate"); add_eval(e)
    e.add_argument("--stream", required=True); e.add_argument("--results", required=True)
    rp = sub.add_parser("report"); rp.add_argument("--results", required=True); rp.add_argument("--report-k", type=int)
    d = sub.add_parser("dry-run"); add_rec(d); add_eval(d); d.add_argument("--results", required=True)
    ar = sub.add_parser("attack-record")
    ar.add_argument("--scenario", choices=["A3a", "A3b"], required=True)
    ar.add_argument("--out", required=True); ar.add_argument("--benign", required=True)
    ar.add_argument("--tasks", type=int, default=20); ar.add_argument("--task-seed", type=int, default=1)
    ar.add_argument("--logging-point", choices=["gateway", "agent"])
    ar.add_argument("--offline", action="store_true")
    ar.add_argument("--mode", help="offline scripted attacker mode: wipe|scrub|none (A3a), omit|honest (A3b)")
    ae = sub.add_parser("attack-eval"); add_eval(ae)
    ae.add_argument("--attacks", required=True); ae.add_argument("--benign", required=True)
    ae.add_argument("--results", required=True)
    a = p.parse_args(argv)

    if a.cmd == "attack-record":
        _attack_record(a)
    elif a.cmd == "attack-eval":
        from .attack_eval import evaluate_attacks, make_attack_report
        ks = [x for x in a.k] if a.k != [10, 50, 100, 500] else [10, 50]
        evaluate_attacks(a.attacks, a.benign, a.results, ks=ks, opts=_opts(a))
        print(make_attack_report(a.results))
    elif a.cmd == "record":
        _record(a, a.offline)
    elif a.cmd == "evaluate":
        meta = evaluate(a.stream, a.results, ks=a.k, opts=_opts(a))
        print(make_report(a.results, a.report_k))
    elif a.cmd == "report":
        print(make_report(a.results, a.report_k))
    else:
        _record(a, True)
        evaluate(a.out, a.results, ks=a.k, opts=_opts(a))
        print(make_report(a.results, a.report_k))


if __name__ == "__main__":
    sys.exit(main())
