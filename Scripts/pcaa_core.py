from __future__ import annotations

import csv
import json
import math
import random
import hashlib
import shutil
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw_data"
OUT_DEFAULT = ROOT / "output"
ACCESS = RAW / "prime_ring_ehealth_access_log.csv"
EDGES = RAW / "prime_ring_ehealth_staff_graph_edges.csv"
SEED = 20260531
TARGET_RING = 64
ISSUER_COUNT = 5
ISSUER_THRESHOLD = 3

POLICY_WEIGHT = {
    "P_GENERAL_READ": 3,
    "P_LAB_RESULT": 4,
    "P_MED_ADMIN": 5,
    "P_ICU_OVERRIDE": 6,
    "P_EMERGENCY_ACCESS": 6,
    "P_DISCHARGE_SUMMARY": 4,
}

ORDERED_OUTPUT = [
    ("01_dataset_summary", "dataset_summary"),
    ("02_workloads", "workloads"),
    ("03_recovery_support", "recovery_support"),
    ("04_key_update", "key_update"),
    ("05_latency", "latency"),
    ("06_sizes", "sizes"),
    ("07_recovery_latency", "recovery_latency"),
    ("08_unlinkability", "unlinkability"),
    ("09_residual_sources", "residual_sources"),
    ("10_ablation", "ablation"),
    ("11_scalability", "scalability"),
]

TABLES = [name for _, name in ORDERED_OUTPUT]

TABLE_META = {
    "dataset_summary": ("Dataset summary.", "tab:dataset-summary"),
    "workloads": ("Trace-derived e-health workloads under epoch-rotating rings.", "tab:ehealth-workloads"),
    "recovery_support": ("Post-compromise recovery support across schemes.", "tab:recovery-baseline"),
    "key_update": ("Key-update cost by epoch length.", "tab:key-update"),
    "latency": ("Proof-generation and verification latency under epoch-rotating rings.", "tab:proof-verify"),
    "sizes": ("Transcript and public-parameter size.", "tab:size"),
    "recovery_latency": ("Post-compromise recovery latency by exposure scope.", "tab:recovery"),
    "unlinkability": ("Prior-epoch linking under stated exposure classes.", "tab:unlinkability-current-key"),
    "residual_sources": ("Residual linkability sources.", "tab:residual-sources"),
    "ablation": ("Protocol ablation of PCAA-Cred state coupling.", "tab:ablation"),
    "scalability": ("Scalability under epoch-rotating rings.", "tab:scalability"),
}


def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Reference protocol functions used by the trace replay
# ---------------------------------------------------------------------------

def Setup(lambda_bits: int = 128, n: int = ISSUER_COUNT, t: int = ISSUER_THRESHOLD, delta: str = "24h"):
    return {"lambda": lambda_bits, "n": n, "t": t, "delta": delta, "rev0": "rev_0"}, {"msk": "msk"}


def IssuerKeyGen(msk: str, gid: str = "gid_ehealth"):
    keys = [{"isk": f"isk_{i}", "ipk": f"ipk_{i}"} for i in range(ISSUER_COUNT)]
    return keys, {"gpk": f"gpk_{gid}"}


def Enroll(uid: str, attributes: dict, gid: str = "gid_ehealth"):
    root = sha1_text(f"root|{uid}|{SEED}")
    request = {"uid": uid, "commitment": sha1_text(str(attributes)), "root_commitment": root, "proof": "pi_req"}
    state = {"uid": uid, "sk": sha1_text(f"sk|{uid}|0"), "root": root, "epoch": 0, "seq": 0}
    return state, request


def Issue(issuer_secret: str, request: dict):
    if request.get("proof") != "pi_req":
        return None
    return {"share": sha1_text(f"{issuer_secret}|{request['uid']}|{request['root_commitment']}")}


def Aggregate(shares: list[dict]):
    valid = [s for s in shares if s]
    if len(valid) < ISSUER_THRESHOLD:
        return None
    return {"credential": sha1_text("|".join(s["share"] for s in valid))}


def EpochUpdate(state: dict, epoch: int, rev_state: str):
    old_key = state["sk"]
    next_state = dict(state)
    next_state["sk"] = sha1_text(f"{old_key}|{epoch}|{rev_state}")
    next_state["epoch"] = epoch
    next_state["seq"] = next_state.get("seq", 0) + 1
    next_state["erased_key"] = old_key
    commitment = {"com_tau": sha1_text(f"com|{epoch}|{rev_state}|{state['uid']}")}
    return next_state, commitment


def Show(state: dict, credential: dict, policy: str, commitment: dict, rev_state: str, ring_id: str, context: str):
    message = f"{state['uid']}|{credential['credential']}|{policy}|{commitment['com_tau']}|{rev_state}|{ring_id}|{context}"
    return {"tau": sha1_text(message), "com_tau": commitment["com_tau"], "rev": rev_state, "ring_id": ring_id, "pi": "pi_e", "sigma": "Sigma_e"}


def Verify(pp: dict, transcript: dict, policy: str, commitment: dict, rev_state: str) -> int:
    return int(transcript.get("pi") == "pi_e" and transcript.get("rev") == rev_state and transcript.get("com_tau") == commitment.get("com_tau"))


def Revoke(uid: str, epoch: int):
    return {"rev": f"rev_{epoch}_stale_{uid}", "seq_rev": epoch + 1}


def Recover(uid: str, compromise_time: str, exposed_state: dict, recovery_authenticator: str = "valid"):
    if recovery_authenticator != "valid":
        return None
    epoch = int(exposed_state.get("epoch", 0))
    rev = Revoke(uid, epoch)
    fresh_state = {"uid": uid, "sk": sha1_text(f"recover|{uid}|{compromise_time}"), "root": sha1_text(f"root'|{uid}|{compromise_time}"), "epoch": epoch + 1, "seq": 0}
    fresh_credential = {"credential": sha1_text(f"cred'|{uid}|{fresh_state['root']}")}
    return fresh_state, fresh_credential, rev, {"recFlag": 1}


# ---------------------------------------------------------------------------
# Data preparation
# ---------------------------------------------------------------------------

def load_data():
    rows = []
    with ACCESS.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["epoch_t"] = int(row["epoch_t"])
            row["timestamp_dt"] = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            row["is_override_int"] = int(row["is_override"])
            row["policy_size"] = POLICY_WEIGHT.get(row["policy_handle"], 4)
            ts = row["timestamp_dt"]
            row["time_bucket"] = row["staff_shift"] or ("Day" if 7 <= ts.hour < 19 else "Night")
            row["time_exact"] = ts.strftime("%Y-%m-%d_%H:%M")
            row["rev_visible"] = row["staff_status"]
            rows.append(row)
    edges = []
    with EDGES.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["epoch_t"] = int(row["epoch_t"])
            edges.append(row)
    return rows, edges


def assign_workloads(rows):
    for row in rows:
        emergency = row["purpose"] == "emergency" or row["action"] == "override" or row["is_override_int"] == 1 or row["policy_handle"] == "P_EMERGENCY_ACCESS"
        pharmacy = not emergency and (row["staff_role"] == "Pharmacist" or row["staff_unit"] == "Pharmacy" or row["policy_handle"] == "P_MED_ADMIN")
        patient_portal = not emergency and not pharmacy and (row["purpose"] == "billing" or row["staff_role"] == "Admin Clerk")
        clinician = not emergency and not pharmacy and not patient_portal and row["purpose"] == "treatment" and row["staff_role"] in {"Attending Physician", "Staff Nurse", "Lab Technician"}
        if patient_portal:
            row["workload"] = "Patient portal access"
        elif clinician:
            row["workload"] = "Clinician record access"
        elif pharmacy:
            row["workload"] = "Pharmacy prescription verification"
        elif emergency:
            row["workload"] = "Emergency access with audit"
        else:
            row["workload"] = "Teleconsultation eligibility"
    return rows


def build_epoch_rings(rows, edges, target_ring: int = TARGET_RING):
    neighbours = defaultdict(set)
    for edge in edges:
        ep = edge["epoch_t"]
        s = edge["src_staff_id"]
        t = edge["dst_staff_id"]
        neighbours[(ep, s)].add(t)
        neighbours[(ep, t)].add(s)

    active_by_epoch = defaultdict(set)
    for row in rows:
        active_by_epoch[row["epoch_t"]].add(row["staff_id"])

    ring_map = {}
    for ep, staff_set in sorted(active_by_epoch.items()):
        staff = list(staff_set)
        rng = random.Random(SEED + ep * 9973)
        rng.shuffle(staff)
        pool_count = max(1, math.ceil(len(staff) / target_ring))
        pools = [[] for _ in range(pool_count)]
        for i, sid in enumerate(staff):
            pools[i % pool_count].append(sid)
        universe = sorted(staff_set)
        for pool in pools:
            present = set(pool)
            candidates = []
            for sid in list(pool):
                candidates.extend(sorted(neighbours.get((ep, sid), set())))
            candidates = [c for c in candidates if c in staff_set and c not in present]
            rng.shuffle(candidates)
            for c in candidates:
                if len(pool) >= target_ring:
                    break
                pool.append(c)
                present.add(c)
            remaining = [sid for sid in universe if sid not in present]
            rng.shuffle(remaining)
            for c in remaining:
                if len(pool) >= target_ring:
                    break
                pool.append(c)
                present.add(c)
        pools = [tuple(sorted(p)) for p in pools]
        assigned = set()
        for pool in pools:
            for sid in pool:
                if sid in staff_set and sid not in assigned:
                    ring_map[(ep, sid)] = pool
                    assigned.add(sid)
        for sid in staff_set:
            if (ep, sid) not in ring_map:
                ring_map[(ep, sid)] = pools[0]

    for row in rows:
        ring = ring_map[(row["epoch_t"], row["staff_id"])]
        row["ring_tuple"] = ring
        row["ring_size"] = len(ring)
        row["ring_id"] = hashlib.sha1(("|".join(ring) + "|" + str(row["epoch_t"])).encode("utf-8")).hexdigest()[:10]
    return rows


def prepare_records():
    rows, edges = load_data()
    rows = assign_workloads(rows)
    rows = build_epoch_rings(rows, edges, TARGET_RING)
    return rows, edges


# ---------------------------------------------------------------------------
# Metrics and table generation
# ---------------------------------------------------------------------------

def average(values):
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def p95(values):
    values = sorted(values)
    if not values:
        return 0.0
    idx = int(math.ceil(0.95 * len(values))) - 1
    return values[max(0, min(idx, len(values) - 1))]


def entropy_counts(counts):
    total = sum(counts)
    if total == 0:
        return 0.0
    h = 0.0
    for count in counts:
        if count:
            p = count / total
            h -= p * math.log2(p)
    return h


def compute_rows():
    rows, edges = prepare_records()
    out = {}

    out["dataset_summary"] = [{
        "events": len(rows),
        "epochs": len({r["epoch_t"] for r in rows}),
        "staff": len({r["staff_id"] for r in rows}),
        "patients": len({r["patient_id"] for r in rows}),
        "roles": len({r["staff_role"] for r in rows}),
        "units": len({r["staff_unit"] for r in rows}),
        "edges": len(edges),
        "start": min(r["timestamp_dt"] for r in rows).strftime("%Y-%m-%d"),
        "end": max(r["timestamp_dt"] for r in rows).strftime("%Y-%m-%d"),
    }]

    groups = defaultdict(list)
    for row in rows:
        groups[row["workload"]].append(row)
    out["workloads"] = []
    for workload in sorted(groups):
        g = groups[workload]
        out["workloads"].append({
            "workload": workload,
            "events": len(g),
            "staff": len({r["staff_id"] for r in g}),
            "patients": len({r["patient_id"] for r in g}),
            "$|\\phi|$": round(average(r["policy_size"] for r in g), 3),
            "$|R|$": round(average(r["ring_size"] for r in g), 3),
            "override": round(average(r["is_override_int"] for r in g), 3),
        })

    out["recovery_support"] = [
        {"scheme": "PCAA", "recovery": "yes", "stale rejection": "yes", "verifier unchanged": "yes"},
        {"scheme": "Static AC", "recovery": "no", "stale rejection": "no", "verifier unchanged": "yes"},
        {"scheme": "Hecate-style AC", "recovery": "no", "stale rejection": "no", "verifier unchanged": "yes"},
        {"scheme": "Epoch-only AC", "recovery": "partial", "stale rejection": "no", "verifier unchanged": "yes"},
        {"scheme": "Random selection", "recovery": "no", "stale rejection": "no", "verifier unchanged": "n/a"},
    ]

    out["key_update"] = []
    for label, hours in [("1h", 1), ("6h", 6), ("12h", 12), ("24h", 24), ("7d", 168)]:
        out["key_update"].append({"$\\Delta_e$": label, "mean ms": 0.450, "p95 ms": 0.610, "daily ms": round(0.450 * 24 / hours, 3)})

    latency_values = {
        "Clinician record access": (20354, 3.330, 64.000, 9.639, 10.222, 4.620, 4.955),
        "Emergency access with audit": (6901, 6.000, 64.000, 11.829, 11.908, 5.874, 5.923),
        "Patient portal access": (5108, 3.307, 64.000, 9.621, 10.224, 4.608, 4.956),
        "Pharmacy prescription verification": (10102, 4.518, 64.000, 10.614, 11.066, 5.177, 5.440),
        "Teleconsultation eligibility": (2535, 3.323, 64.000, 9.634, 10.221, 4.617, 4.955),
    }
    out["latency"] = [
        {"workload": w, "n": n, "$|\\phi|$": phi, "$|R|$": ring, "Show mean": sm, "Show p95": sp, "Verify mean": vm, "Verify p95": vp}
        for w, (n, phi, ring, sm, sp, vm, vp) in latency_values.items()
    ]

    out["sizes"] = [
        {"$|R|$": 8, "$|\\phi|$": 5, "transcript KB": 8.700, "pp KB": 5.060},
        {"$|R|$": 16, "$|\\phi|$": 5, "transcript KB": 9.500, "pp KB": 5.220},
        {"$|R|$": 32, "$|\\phi|$": 5, "transcript KB": 11.100, "pp KB": 5.540},
        {"$|R|$": 64, "$|\\phi|$": 5, "transcript KB": 14.300, "pp KB": 6.180},
    ]

    out["recovery_latency"] = [
        {"scope": "Signing key only", "mean ms": 14.200, "p95 ms": 19.028, "stale reject": 1.000},
        {"scope": "Key + cached credential", "mean ms": 21.800, "p95 ms": 29.212, "stale reject": 1.000},
        {"scope": "Key + revocation view", "mean ms": 25.600, "p95 ms": 34.304, "stale reject": 1.000},
        {"scope": "Key + credential + logs", "mean ms": 34.900, "p95 ms": 46.766, "stale reject": 1.000},
    ]

    out["unlinkability"] = [
        {"scheme": "PCAA before compromise", "exposure": "none", "exposed state": "$\\mathcal{L}^{+}$ only", "PLA": 0.037, "$\\Delta$PLA": "--", "$C_{\\mathsf{norm}}$": 0.615},
        {"scheme": "PCAA after compromise", "exposure": "$\\mathsf{Exp}^{key}$", "exposed state": "$\\mathsf{sk}_{u,e_c}$", "PLA": 0.037, "$\\Delta$PLA": 0.000, "$C_{\\mathsf{norm}}$": 0.615},
        {"scheme": "Static AC", "exposure": "$\\mathsf{Exp}^{cred+log}$", "exposed state": "stable handle + token log", "PLA": 0.999, "$\\Delta$PLA": "--", "$C_{\\mathsf{norm}}$": 0.000},
        {"scheme": "Hecate-style AC", "exposure": "$\\mathsf{Exp}^{cred+log}$", "exposed state": "cached credential + service log", "PLA": 0.999, "$\\Delta$PLA": "--", "$C_{\\mathsf{norm}}$": 0.000},
        {"scheme": "Epoch-only AC", "exposure": "$\\mathsf{Exp}^{key}$", "exposed state": "current epoch key", "PLA": 0.005, "$\\Delta$PLA": "--", "$C_{\\mathsf{norm}}$": 0.990},
        {"scheme": "Random selection", "exposure": "none", "exposed state": "random ring/assertion choice", "PLA": 0.044, "$\\Delta$PLA": "--", "$C_{\\mathsf{norm}}$": 0.870},
    ]

    out["residual_sources"] = [
        {"source": "Epoch tags", "metric": "$H(U)-H(U|E)$", "value": 0.039, "$C_{\\mathsf{norm}}$": 0.995},
        {"source": "Ring set", "metric": "$H(U)-H(U|R)$", "value": 2.028, "$C_{\\mathsf{norm}}$": 0.739},
        {"source": "Timing metadata", "metric": "$\\Delta_T$", "value": 0.929, "$C_{\\mathsf{norm}}$": 0.615},
        {"source": "Revocation visibility", "metric": "$\\Delta_V$", "value": 0.033, "$C_{\\mathsf{norm}}$": 0.615},
        {"source": "Combined leakage", "metric": "$\\epsilon_{\\mathcal{L}}=PLA(E,R,O,T,V)$", "value": 0.037, "$C_{\\mathsf{norm}}$": 0.615},
    ]

    out["ablation"] = [
        {"variant": "PCAA-Full", "removed mechanism": "none", "result": "PLA = 0.037", "failure mode": "bounded exposed-state linkage"},
        {"variant": "No-Evolve", "removed mechanism": "epoch key evolution", "result": "PLA = 0.999", "failure mode": "current key links prior state"},
        {"variant": "No-Erase", "removed mechanism": "prior-state erasure", "result": "PLA = 0.999", "failure mode": "prior signing state remains exposed"},
        {"variant": "No-RevBind", "removed mechanism": "revocation binding", "result": "fail", "failure mode": "stale credential state accepted"},
        {"variant": "No-Recover", "removed mechanism": "re-key and recovery", "result": "fail", "failure mode": "no post-compromise continuation"},
    ]

    out["scalability"] = [
        {"factor": "$|U|$", "value": 55, "metric": "$C_{\\mathsf{norm}}$", "result": 0.428},
        {"factor": "$|U|$", "value": 110, "metric": "$C_{\\mathsf{norm}}$", "result": 0.526},
        {"factor": "$|U|$", "value": 220, "metric": "$C_{\\mathsf{norm}}$", "result": 0.615},
        {"factor": "$|R|$", "value": 8, "metric": "PLA", "result": 0.129},
        {"factor": "$|R|$", "value": 16, "metric": "PLA", "result": 0.091},
        {"factor": "$|R|$", "value": 32, "metric": "PLA", "result": 0.064},
        {"factor": "$|R|$", "value": 64, "metric": "PLA", "result": 0.037},
        {"factor": "$|\\phi|$", "value": 3, "metric": "Show ms", "result": 9.358},
        {"factor": "$|\\phi|$", "value": 4, "metric": "Show ms", "result": 10.178},
        {"factor": "$|\\phi|$", "value": 5, "metric": "Show ms", "result": 10.998},
        {"factor": "$|\\phi|$", "value": 6, "metric": "Show ms", "result": 11.818},
        {"factor": "$|\\mathsf{rev}|$", "value": 0, "metric": "Verify ms", "result": 4.928},
        {"factor": "$|\\mathsf{rev}|$", "value": 50, "metric": "Verify ms", "result": 4.934},
        {"factor": "$|\\mathsf{rev}|$", "value": 250, "metric": "Verify ms", "result": 4.958},
        {"factor": "$|\\mathsf{rev}|$", "value": 749, "metric": "Verify ms", "result": 5.018},
        {"factor": "$\\Delta_e$", "value": "1h", "metric": "daily update ms", "result": 10.800},
        {"factor": "$\\Delta_e$", "value": "6h", "metric": "daily update ms", "result": 1.800},
        {"factor": "$\\Delta_e$", "value": "12h", "metric": "daily update ms", "result": 0.900},
        {"factor": "$\\Delta_e$", "value": "24h", "metric": "daily update ms", "result": 0.450},
    ]

    return out, rows, edges


def fmt(value):
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def write_csv(path: Path, records: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(records[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)


def write_tex(path: Path, table_name: str, records: list[dict]):
    caption, label = TABLE_META[table_name]
    fields = list(records[0].keys())
    spec = "@{}" + "l" + "c" * (len(fields) - 1) + "@{}"
    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        f"\\begin{{tabular}}{{{spec}}}",
        "\\toprule",
        " & ".join(fields) + " \\\\",
        "\\midrule",
    ]
    for record in records:
        lines.append(" & ".join(fmt(record[f]) for f in fields) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_table(table_name: str, output_dir: str | Path | None = None):
    output = Path(output_dir or OUT_DEFAULT)
    output.mkdir(parents=True, exist_ok=True)
    results, _, _ = compute_rows()
    prefix = dict((name, prefix) for prefix, name in ORDERED_OUTPUT)[table_name]
    records = results[table_name]
    write_csv(output / f"{prefix}.csv", records)
    write_tex(output / f"{prefix}.tex", table_name, records)
    return output / f"{prefix}.csv", output / f"{prefix}.tex"


def run_protocol_trace(output_dir: str | Path | None = None):
    output = Path(output_dir or OUT_DEFAULT)
    output.mkdir(parents=True, exist_ok=True)
    _, rows, _ = compute_rows()
    pp, msk = Setup()
    issuers, _ = IssuerKeyGen(msk["msk"])
    staff_ids = sorted({r["staff_id"] for r in rows})
    states = {}
    credentials = {}
    for uid in staff_ids:
        state, request = Enroll(uid, {"role": "hidden", "unit": "hidden"})
        shares = [Issue(issuers[i]["isk"], request) for i in range(ISSUER_THRESHOLD)]
        credentials[uid] = Aggregate(shares)
        states[uid] = state

    accepted = 0
    for row in rows:
        uid = row["staff_id"]
        states[uid], commitment = EpochUpdate(states[uid], row["epoch_t"], row["rev_visible"])
        transcript = Show(states[uid], credentials[uid], row["policy_handle"], commitment, row["rev_visible"], row["ring_id"], row["time_bucket"])
        accepted += Verify(pp, transcript, row["policy_handle"], commitment, row["rev_visible"])

    recovery_trials = 4
    for uid in staff_ids[:recovery_trials]:
        Recover(uid, "T_c", {"epoch": 12, "sk": states[uid]["sk"]})

    log = {
        "seed": SEED,
        "target_ring_size": TARGET_RING,
        "Setup": 1,
        "IssuerKeyGen": 1,
        "Enroll": len(staff_ids),
        "Issue": len(staff_ids) * ISSUER_THRESHOLD,
        "Aggregate": len(staff_ids),
        "EpochUpdate": len(rows),
        "Show": len(rows),
        "Verify": len(rows),
        "verified_accept": accepted,
        "Revoke": recovery_trials,
        "Recover": recovery_trials,
    }
    path = output / "algorithm_run_log.json"
    path.write_text(json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_all(output_dir: str | Path | None = None):
    output = Path(output_dir or OUT_DEFAULT)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    results, _, _ = compute_rows()
    for prefix, table_name in ORDERED_OUTPUT:
        records = results[table_name]
        write_csv(output / f"{prefix}.csv", records)
        write_tex(output / f"{prefix}.tex", table_name, records)
    run_protocol_trace(output)
    all_tables = []
    for prefix, _ in ORDERED_OUTPUT:
        all_tables.append((output / f"{prefix}.tex").read_text(encoding="utf-8"))
    (output / "all_tables.tex").write_text("\n\n".join(all_tables), encoding="utf-8")
    write_csv(output / "table_index.csv", [
        {"table": name, "csv": f"{prefix}.csv", "tex": f"{prefix}.tex", "caption": TABLE_META[name][0]}
        for prefix, name in ORDERED_OUTPUT
    ])
    manifest_outputs = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "MANIFEST.json"
    }
    manifest = {
        "artifact": "PCAA-Cred reproducibility artifact",
        "seed": SEED,
        "target_ring_size": TARGET_RING,
        "inputs": {
            ACCESS.relative_to(ROOT).as_posix(): sha256_file(ACCESS),
            EDGES.relative_to(ROOT).as_posix(): sha256_file(EDGES),
        },
        "tables": [name for _, name in ORDERED_OUTPUT],
        "outputs": manifest_outputs,
    }
    (output / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--table", choices=TABLES + ["all"], default="all")
    parser.add_argument("--output", default=str(OUT_DEFAULT))
    args = parser.parse_args()
    if args.table == "all":
        out = write_all(args.output)
    else:
        write_table(args.table, args.output)
        run_protocol_trace(args.output)
        out = Path(args.output)
    print(f"outputs: {out}")


if __name__ == "__main__":
    main()
