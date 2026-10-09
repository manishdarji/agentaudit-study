"""Replay a recorded stream into M0-M4, attack every log, verify, and measure cost.

Geometry: with N events and anchor interval k, the last anchor covers L = (N // k) * k events.
Entries before L are 'history' (anchored); entries from L on are the 'tail' (the unanchored window).
"""
import csv
import json
import os
import shutil
import statistics
import time
from dataclasses import dataclass, field

from .. import attacks
from ..anchors import AnchoredLog, MissingDependency
from ..loggers import ChainedLog, PlainLog, generate_keypair
from ..verify import verify_chained, verify_plain
from .record import load_stream, load_truth

MECHS = ["M0", "M1", "M2", "M3", "M4"]
ASSUMPTIONS = {"gas_price_gwei_l1": 30.0, "gas_price_gwei_l2": 0.01, "eth_usd": 2500.0,
               "note": "execution gas only; L2 data fees not included"}
FORGED = {"run": "forged", "step": 0, "n": 0, "kind": "call", "tool": "send_email",
          "args": {"to": "attacker@evil.test", "subject": "x", "body": "x"}, "ts": 0.0}
DETECTION_FIELDS = ["k", "mech", "attacker", "op", "variant", "region", "pos", "N", "L", "detected", "reason"]


@dataclass
class Built:
    mech: str
    path: str
    key: object
    pub: bytes
    N: int
    anchors: list
    receipts: list = field(default_factory=list)
    lat_ms: list = field(default_factory=list)
    deploy_gas: object = None


def make_backend(mech, work, opts):
    try:
        if mech == "M2":
            from ..anchors.tsa import HttpTSA, LocalTSA, TimestampAnchorer
            esc = os.path.join(work, "escrow")
            if opts.get("tsa_url"):
                return TimestampAnchorer(HttpTSA(opts["tsa_url"], opts["tsa_ca"]), esc, opts.get("tsa_untrusted"))
            return TimestampAnchorer(LocalTSA(os.path.join(work, "tsa")), esc)
        if mech == "M3":
            from ..anchors.translog import TransparencyAnchorer, TransparencyLog
            priv, pub = generate_keypair()
            return TransparencyAnchorer(TransparencyLog(priv), pub)
        if mech == "M4":
            from ..anchors.chain import ChainAnchorer, local_chain, rpc_chain
            if opts.get("rpc_url"):
                return ChainAnchorer(rpc_chain(opts["rpc_url"]), private_key=os.environ["ANCHOR_PRIVATE_KEY"],
                                     contract_address=opts.get("contract"))
            return ChainAnchorer(local_chain())
    except ImportError as e:
        raise MissingDependency(f"{mech} needs a package that is not installed: {e}")
    raise ValueError(mech)


def open_log(mech, work, k, opts):
    """Fresh empty log for `mech`. Returns (log, closer, backend, priv, pub, path)."""
    os.makedirs(work, exist_ok=True)
    path = os.path.join(work, "log.db")
    if os.path.exists(path):
        os.remove(path)
    priv, pub = generate_keypair()
    backend = None
    if mech == "M0":
        log = closer = PlainLog(path)
    else:
        closer = ChainedLog(path, priv)
        log = closer
        if mech != "M1":
            backend = make_backend(mech, work, opts)
            log = AnchoredLog(closer, backend, k)
    return log, closer, backend, priv, pub, path


def build_log(mech, events, work, k, opts, skip=None):
    """Replay events into a fresh log. `skip` = index of one event that is never written (omission)."""
    log, closer, backend, priv, pub, path = open_log(mech, work, k, opts)
    lat, n = [], 0
    for i, ev in enumerate(events):
        if skip is not None and i == skip:
            continue
        t0 = time.perf_counter()
        log.append(ev)
        lat.append((time.perf_counter() - t0) * 1000)
        n += 1
    closer.close()
    anchors = backend.published() if backend else None
    return Built(mech, path, priv, pub, n, anchors, getattr(log, "receipts", []), lat,
                 getattr(backend, "deploy_gas", None))


def make_specs(N, L):
    cand = sorted({p for p in (0, L // 2, L - 1, L, (L + N) // 2, N - 2, N - 1) if 0 <= p <= N - 1})
    out = []
    for attacker, variants in (("A1", ("naive", "rehash")), ("A2", ("resign",))):
        for variant in variants:
            for op in ("edit", "delete", "reorder", "insert"):
                seen = set()
                for p in cand:
                    q = min(p, N - 2) if op == "reorder" else p
                    if op == "delete" and attacker == "A1" and q == N - 1:
                        continue  # deleting the very last entry is a truncation; measured separately
                    if q in seen:
                        continue
                    seen.add(q)
                    out.append({"attacker": attacker, "op": op, "variant": variant, "pos": q,
                                "region": "history" if q < L else "tail"})
    for n in sorted({1, (N - L) + 1, N // 2}):
        if 1 <= n < N:
            out.append({"attacker": "A1", "op": "truncate", "variant": f"drop{n}", "pos": N - n,
                        "region": "past_anchor" if N - n < L else "within_window"})
    return out


def _apply(path, spec, key):
    rehash = spec["variant"] == "rehash"
    kk = key if spec["attacker"] == "A2" else None
    op, p = spec["op"], spec["pos"]
    if op == "edit":
        attacks.edit_entry(path, p, rehash=rehash, key=kk)
    elif op == "delete":
        attacks.delete_entry(path, p, rehash=rehash, key=kk)
    elif op == "reorder":
        attacks.reorder_entries(path, p, p + 1, rehash=rehash, key=kk)
    elif op == "insert":
        attacks.insert_entry(path, p, FORGED, rehash=rehash, key=kk)
    elif op == "truncate":
        attacks.truncate_tail(path, spec["N"] - p)
    else:
        raise ValueError(op)


def verify_built(built, path):
    if built.mech == "M0":
        return verify_plain(path)
    return verify_chained(path, built.pub, built.anchors)


def attack_trials(built, k, L, work):
    rows = []
    tmp = os.path.join(work, "trial.db")

    def row(spec, res):
        return {"k": k, "mech": built.mech, "attacker": spec["attacker"], "op": spec["op"],
                "variant": spec["variant"], "region": spec["region"], "pos": spec["pos"], "N": built.N,
                "L": L, "detected": int(not res.ok), "reason": res.reason}

    base = {"attacker": "none", "op": "none", "variant": "-", "pos": -1, "region": "-"}
    rows.append(row(base, verify_built(built, built.path)))
    for spec in make_specs(built.N, L):
        spec = dict(spec, N=built.N)
        shutil.copyfile(built.path, tmp)
        _apply(tmp, spec, built.key)
        rows.append(row(spec, verify_built(built, tmp)))
    return rows


def _pct(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]


def cost_row(built, k, N, assumptions):
    a = assumptions
    r = {"k": k, "mech": built.mech, "N": N,
         "append_ms_p50": round(statistics.median(built.lat_ms), 3),
         "append_ms_p95": round(_pct(built.lat_ms, 0.95), 3),
         "append_ms_p99": round(_pct(built.lat_ms, 0.99), 3),
         "n_anchors": len(built.receipts), "publish_ms_p50": "", "gas_per_anchor": "", "bytes_per_anchor": "",
         "deploy_gas": built.deploy_gas if built.deploy_gas is not None else "",
         "window_events": (k - 1) if built.mech in ("M2", "M3", "M4") else N,
         "db_bytes": os.path.getsize(built.path), "usd_per_1k_events_l1": 0.0, "usd_per_1k_events_l2": 0.0}
    if built.receipts:
        r["publish_ms_p50"] = round(statistics.median(x.latency_s for x in built.receipts) * 1000, 3)
        gas = [x.cost["gas"] for x in built.receipts if "gas" in x.cost]
        byt = [x.cost["bytes"] for x in built.receipts if "bytes" in x.cost]
        if gas:
            g = statistics.median(gas)
            r["gas_per_anchor"] = int(g)
            per = 1000.0 / k
            r["usd_per_1k_events_l1"] = round(g * a["gas_price_gwei_l1"] * 1e-9 * a["eth_usd"] * per, 4)
            r["usd_per_1k_events_l2"] = round(g * a["gas_price_gwei_l2"] * 1e-9 * a["eth_usd"] * per, 6)
        if byt:
            r["bytes_per_anchor"] = int(statistics.median(byt))
    return r


def coverage(stream, truth, logging_point):
    kind = "call" if logging_point == "gateway" else "agent_log"
    logged = sum(1 for e in stream if e["kind"] == kind)
    per = {}
    for t in truth:
        per.setdefault(t["tool"], [0, 0])[0] += 1
    for e in stream:
        if e["kind"] == kind:
            per.setdefault(e["tool"], [0, 0])[1] += 1
    return {"truth_calls": len(truth), "logged_calls": logged,
            "coverage": round(min(1.0, logged / len(truth)), 4) if truth else None,
            "per_tool": {t: {"truth": a, "logged": min(a, b)} for t, (a, b) in sorted(per.items())}}


def evaluate(stream_dir, out_dir, ks=(10, 50, 100, 500), opts=None, mechs=MECHS, assumptions=None,
             progress=print):
    opts = opts or {}
    a = dict(ASSUMPTIONS, **(assumptions or {}))
    events = load_stream(stream_dir)
    truth = load_truth(stream_dir)
    if len(events) < 4:
        raise ValueError(f"stream in {stream_dir} has only {len(events)} events; record more tasks first")
    with open(os.path.join(stream_dir, "record_meta.json")) as f:
        rec = json.load(f)
    N = len(events)
    os.makedirs(out_dir, exist_ok=True)
    work_root = os.path.join(out_dir, "_work")
    det, cost, skipped = [], [], {}
    for k in ks:
        L = (N // k) * k
        for mech in mechs:
            if mech in skipped:
                continue
            work = os.path.join(work_root, f"k{k}_{mech}")
            try:
                built = build_log(mech, events, work, k, opts)
            except MissingDependency as e:
                skipped[mech] = str(e)
                progress(f"  skip {mech}: {e}")
                continue
            progress(f"k={k} {mech}: built {built.N} events, {len(built.receipts)} anchors")
            det += attack_trials(built, k, L, work)
            cost.append(cost_row(built, k, N, a))
            for label, idx in (("middle", N // 2), ("last", N - 1)):
                om = build_log(mech, events, work + "_omit", k, opts, skip=idx)
                res = verify_built(om, om.path)
                det.append({"k": k, "mech": mech, "attacker": "A3b", "op": "omit", "variant": label,
                            "region": "-", "pos": idx, "N": om.N, "L": L, "detected": int(not res.ok),
                            "reason": res.reason})
    shutil.rmtree(work_root, ignore_errors=True)
    with open(os.path.join(out_dir, "detection.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=DETECTION_FIELDS)
        w.writeheader()
        w.writerows(det)
    with open(os.path.join(out_dir, "cost.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(cost[0]) if cost else ["k"])
        w.writeheader()
        w.writerows(cost)
    meta = {"logging_point": rec["logging_point"], "model": rec.get("model"), "events": N, "ks": list(ks),
            "assumptions": a, "skipped": skipped, "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "options": {k_: v for k_, v in opts.items() if k_ != "private_key"},
            **coverage(events, truth, rec["logging_point"])}
    try:
        import importlib.metadata as md
        meta["versions"] = {p: md.version(p) for p in ("cryptography", "web3", "vyper", "eth-tester", "py-evm")
                            if _has(md, p)}
    except Exception:
        pass
    with open(os.path.join(out_dir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    return meta


def _has(md, p):
    try:
        md.version(p)
        return True
    except Exception:
        return False
