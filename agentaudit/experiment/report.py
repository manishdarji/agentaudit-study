"""Turn detection.csv / cost.csv into markdown and LaTeX tables ready to paste into the paper."""
import csv
import json
import os

MECHS = ["M0", "M1", "M2", "M3", "M4"]
ROWS = [
    ("Edit entry (A1)", lambda r: r["attacker"] == "A1" and r["op"] == "edit"),
    ("Delete entry (A1)", lambda r: r["attacker"] == "A1" and r["op"] == "delete"),
    ("Reorder entries (A1)", lambda r: r["attacker"] == "A1" and r["op"] == "reorder"),
    ("Insert forged entry (A1)", lambda r: r["attacker"] == "A1" and r["op"] == "insert"),
    ("Truncate tail (A1)", lambda r: r["op"] == "truncate"),
    ("Rewrite tail (A2)", lambda r: r["attacker"] == "A2" and r["region"] == "tail"),
    ("Fork history (A2)", lambda r: r["attacker"] == "A2" and r["region"] == "history"),
    ("Omit event (A3b)", lambda r: r["attacker"] == "A3b"),
]


def read_csv(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for c in ("k", "pos", "N", "L", "detected"):
            if c in r and r[c] != "":
                r[c] = int(r[c])
    return rows


def rate(rows, mech, pred):
    sel = [r for r in rows if r["mech"] == mech and pred(r)]
    return sum(r["detected"] for r in sel), len(sel)


def fmt(h, t):
    return "--" if t == 0 else f"{100.0 * h / t:.0f}"


def _tex(s):
    return s.replace("&", r"\&").replace("%", r"\%").replace("$", r"\$").replace("_", r"\_")


def _table_tex(caption, label, header, body, spec):
    lines = [r"\begin{table}[t]", r"\caption{" + caption + "}", r"\label{" + label + "}", r"\centering",
             r"\begin{tabular}{" + spec + "}", r"\hline", " & ".join(header) + r" \\", r"\hline"]
    lines += [" & ".join(_tex(str(c)) for c in r) + r" \\" for r in body]
    lines += [r"\hline", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


def _md(header, body):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in body]
    return "\n".join(out)


def detection_table(det, k, present):
    rows = [r for r in det if r["k"] == k]
    body = []
    for label, pred in ROWS:
        body.append([label] + [fmt(*rate(rows, m, pred)) if m in present else "n/a" for m in MECHS])
    fp = [fmt(*rate(rows, m, lambda r: r["attacker"] == "none")) if m in present else "n/a" for m in MECHS]
    body.append(["(false alarms, untouched log)"] + fp)
    return ["Attack"] + MECHS, body


def sweep_table(det, ks, present):
    body = []
    for k in ks:
        rows = [r for r in det if r["k"] == k]
        if not rows:
            continue
        n = rows[0]["N"]
        L = rows[0]["L"]
        for m in MECHS[1:]:
            if m not in present:
                continue
            body.append([k, n - L, m,
                         fmt(*rate(rows, m, lambda r: r["op"] == "truncate")),
                         fmt(*rate(rows, m, lambda r: r["attacker"] == "A2" and r["region"] == "tail")),
                         fmt(*rate(rows, m, lambda r: r["attacker"] == "A2" and r["region"] == "history"))])
    return ["k", "Window", "Mech.", "Truncate", "Rewrite tail", "Fork"], body


def cost_table(cost, k, present):
    body = []
    for r in cost:
        if r["k"] != k:
            continue
        body.append([r["mech"], r["append_ms_p50"], r["append_ms_p99"], r["n_anchors"], r["publish_ms_p50"],
                     r["gas_per_anchor"], r["usd_per_1k_events_l1"], r["usd_per_1k_events_l2"], r["window_events"]])
    return ["Mech.", "Append p50 (ms)", "Append p99 (ms)", "Anchors", "Publish p50 (ms)", "Gas/anchor",
            "USD/1k ev. L1", "USD/1k ev. L2", "Max window"], body


def make_report(results_dir, report_k=None):
    det = read_csv(os.path.join(results_dir, "detection.csv"))
    cost = read_csv(os.path.join(results_dir, "cost.csv"))
    with open(os.path.join(results_dir, "meta.json")) as f:
        meta = json.load(f)
    ks = meta["ks"]
    report_k = report_k or (50 if 50 in ks else ks[0])
    present = [m for m in MECHS if m not in meta["skipped"]]
    h1, b1 = detection_table(det, report_k, present)
    h2, b2 = sweep_table(det, ks, present)
    h3, b3 = cost_table(cost, report_k, present)
    a = meta["assumptions"]
    md = [f"# Results ({meta['logging_point']} logging, {meta['events']} events, {meta['ts']})", "",
          f"Model: {meta.get('model')}. Coverage of real tool calls in the log: {meta.get('coverage')} "
          f"({meta.get('logged_calls')} of {meta.get('truth_calls')}).", ""]
    if meta["skipped"]:
        md += ["Skipped mechanisms: " + "; ".join(f"{k_}: {v}" for k_, v in meta["skipped"].items()), ""]
    md += [f"## Detection rate (%), k = {report_k}", "", _md(h1, b1), "",
           "## Sensitivity to anchor interval k", "", _md(h2, b2), "",
           f"## Cost, k = {report_k}", "", _md(h3, b3), "",
           f"Assumptions: L1 gas {a['gas_price_gwei_l1']} gwei, L2 gas {a['gas_price_gwei_l2']} gwei, "
           f"ETH ${a['eth_usd']:.0f}; {a['note']}.", ""]
    with open(os.path.join(results_dir, "results.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    tex = [_table_tex(f"Detection rate (\\%) per attack and mechanism, $k={report_k}$.", "tab:detection", h1, b1,
                      "l" + "c" * len(MECHS)),
           "",
           _table_tex("Detection rate (\\%) as the anchor interval $k$ grows.", "tab:sweep", h2, b2, "cclccc"),
           "",
           _table_tex(f"Measured cost per mechanism, $k={report_k}$.", "tab:cost", h3, b3,
                      "l" + "r" * (len(h3) - 1))]
    with open(os.path.join(results_dir, "tables.tex"), "w", encoding="utf-8") as f:
        f.write("\n".join(tex))
    return "\n".join(md)
