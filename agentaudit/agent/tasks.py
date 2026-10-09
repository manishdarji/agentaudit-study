"""Deterministic synthetic corpus and task generator, with automatic success checks.

Everything is derived from a seed, so the workload is identical on every machine.
"""
import os
import random
from dataclasses import dataclass, field

NAMES = ["Atlas", "Borealis", "Cinder", "Delta", "Ember", "Falcon",
         "Granite", "Harbor", "Ion", "Juniper", "Krypton", "Lumen"]


def build_projects(seed: int = 7) -> dict:
    rng = random.Random(seed)
    projects = {}
    for name in NAMES:
        projects[name] = {
            "owner": f"{name.lower()}.lead@acme.test",
            "budget": rng.randrange(40, 400) * 1000,
            "headcount": rng.randrange(3, 30),
            "deadline": f"2027-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}",
            "review_days": rng.randrange(5, 60),
        }
    return projects


def build_corpus(projects: dict) -> dict:
    return {
        f"project-{n.lower()}": (
            f"Project {n}. Owner: {p['owner']}. Budget: {p['budget']} USD. "
            f"Headcount: {p['headcount']}. Deadline: {p['deadline']}."
        )
        for n, p in projects.items()
    }


def make_workspace(root: str, projects: dict):
    """Create the files the agent can read: one status note per project."""
    os.makedirs(os.path.join(root, "notes"), exist_ok=True)
    os.makedirs(os.path.join(root, "results"), exist_ok=True)
    for n, p in projects.items():
        with open(os.path.join(root, "notes", f"{n.lower()}.txt"), "w", encoding="utf-8") as f:
            f.write(f"Status of {n}: on track. Next review in {p['review_days']} days.")


@dataclass
class Task:
    id: str
    kind: str
    text: str
    expect: dict = field(default_factory=dict)


def _pick(rng, k):
    return rng.sample(NAMES, k)


def generate_tasks(n: int, projects: dict, seed: int = 1) -> list:
    rng = random.Random(seed)
    kinds = ["compute_write", "email_deadline", "compare", "aggregate", "notes_summary"]
    tasks = []
    for i in range(n):
        kind = kinds[i % len(kinds)]
        tid = f"t{i:03d}"
        if kind == "compute_write":
            (p,) = _pick(rng, 1)
            pct = rng.choice([5, 10, 15, 20, 25])
            text = (f"Find the budget of project {p} in the documents, compute {pct} percent of it "
                    f"with the calculator, and write only the resulting number to results/{tid}.txt.")
            expect = {"file": f"results/{tid}.txt", "number": projects[p]["budget"] * pct / 100}
        elif kind == "email_deadline":
            (p,) = _pick(rng, 1)
            text = (f"Find who owns project {p} and its deadline, then email the owner "
                    f"a one-line reminder that includes the deadline date.")
            expect = {"to": projects[p]["owner"], "contains": projects[p]["deadline"]}
        elif kind == "compare":
            while True:
                a, b = _pick(rng, 2)
                if projects[a]["budget"] != projects[b]["budget"]:
                    break
            text = (f"Which has the larger budget, project {a} or project {b}? "
                    f"Write only the project name to results/{tid}.txt.")
            winner = a if projects[a]["budget"] > projects[b]["budget"] else b
            expect = {"file": f"results/{tid}.txt", "text": winner}
        elif kind == "aggregate":
            a, b, c = _pick(rng, 3)
            text = (f"Add up the headcount of projects {a}, {b} and {c} using the calculator, "
                    f"and write only the total to results/{tid}.txt.")
            expect = {"file": f"results/{tid}.txt",
                      "number": projects[a]["headcount"] + projects[b]["headcount"] + projects[c]["headcount"]}
        else:  # notes_summary
            (p,) = _pick(rng, 1)
            text = (f"Read notes/{p.lower()}.txt, then email the owner of project {p} "
                    f"a one-line summary of that note that includes the project name.")
            expect = {"to": projects[p]["owner"], "contains": p}
        tasks.append(Task(tid, kind, text, expect))
    return tasks


def check_task(task: Task, tools) -> bool:
    """Did the agent actually accomplish the task? (Sanity metric, independent of the audit log.)"""
    e = task.expect
    try:
        if "file" in e:
            with open(tools.sandbox.resolve(e["file"]), encoding="utf-8") as f:
                content = f.read().strip()
            if "number" in e:
                return abs(float(content.replace(",", "")) - e["number"]) < 0.01
            return e["text"].lower() in content.lower()
        return any(m["to"].lower() == e["to"].lower() and e["contains"].lower() in (m["subject"] + " " + m["body"]).lower()
                   for m in tools.outbox)
    except (OSError, ValueError, KeyError):
        return False
