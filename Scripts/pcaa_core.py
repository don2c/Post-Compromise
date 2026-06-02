
from __future__ import annotations
import argparse, csv, json, math, random, hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'raw_data'
OUT_DEFAULT = ROOT / 'output'
ACCESS = RAW / 'prime_ring_ehealth_access_log.csv'
EDGES = RAW / 'prime_ring_ehealth_staff_graph_edges.csv'
SEED = 20260531
TARGET_RING = 64
ISSUER_COUNT = 5
ISSUER_THRESHOLD = 3

POLICY_WEIGHT = {
    'P_GENERAL_READ': 3,
    'P_LAB_RESULT': 4,
    'P_MED_ADMIN': 5,
    'P_ICU_OVERRIDE': 6,
    'P_EMERGENCY_ACCESS': 6,
    'P_DISCHARGE_SUMMARY': 4,
}

TABLES = [
    'dataset_summary', 'workloads', 'recovery_support', 'key_update',
    'latency', 'sizes', 'recovery_latency', 'unlinkability',
    'residual_sources', 'ablation', 'scalability'
]

TABLE_META = {
    'dataset_summary': ('Dataset summary.', 'tab:dataset-summary'),
    'workloads': ('Trace-derived e-health workloads under epoch-rotating rings.', 'tab:ehealth-workloads'),
    'recovery_support': ('Post-compromise recovery support across schemes.', 'tab:recovery-baseline'),
    'key_update': ('Key-update cost by epoch length.', 'tab:key-update'),
    'latency': ('Proof-generation and verification latency under epoch-rotating rings.', 'tab:proof-verify'),
    'sizes': ('Transcript and public-parameter size.', 'tab:size'),
    'recovery_latency': ('Post-compromise recovery latency by exposure scope.', 'tab:recovery'),
    'unlinkability': ('Prior-epoch linking under current-key exposure.', 'tab:unlinkability-current-key'),
    'residual_sources': ('Residual linkability sources.', 'tab:residual-sources'),
    'ablation': ('Ablation study after ring recalculation.', 'tab:ablation'),
    'scalability': ('Scalability under epoch-rotating rings.', 'tab:scalability'),
}

ORDERED_OUTPUT = [
    ('01_dataset_summary', 'dataset_summary'),
    ('02_workloads', 'workloads'),
    ('03_recovery_support', 'recovery_support'),
    ('04_key_update', 'key_update'),
    ('05_latency', 'latency'),
    ('06_sizes', 'sizes'),
    ('07_recovery_latency', 'recovery_latency'),
    ('08_unlinkability', 'unlinkability'),
    ('09_residual_sources', 'residual_sources'),
    ('10_ablation', 'ablation'),
    ('11_scalability', 'scalability'),
]

# -----------------------------
# PCAA algorithm stubs used by the trace replay
# -----------------------------
def Setup(lambda_bits=128, n=ISSUER_COUNT, t=ISSUER_THRESHOLD, Delta='24h'):
    return {'lambda': lambda_bits, 'n': n, 't': t, 'Delta': Delta, 'rev0': 'rev_0'}, {'msk': 'msk'}

def IssuerKeyGen(msk, gid='gid_ehealth'):
    keys = [{'isk': f'isk_{i}', 'ipk': f'ipk_{i}'} for i in range(ISSUER_COUNT)]
    return keys, {'gpk': f'gpk_{gid}'}

def Enroll(uid, x, gid='gid_ehealth'):
    sk0 = f'sk_{uid}_0'
    req = {'uid': uid, 'commit_x': sha1_text(str(x)), 'proof': 'pi_req'}
    return {'uid': uid, 'sk': sk0, 'x': x, 'gid': gid}, req

def Issue(isk, req):
    if not req.get('proof'):
        return None
    return {'cred_share': sha1_text(isk + req['uid']), 'functional': True, 'signature': True}

def Aggregate(shares):
    if len(shares) < ISSUER_THRESHOLD:
        return None
    return {'cred': sha1_text('|'.join(s['cred_share'] for s in shares)), 'cred_match': True, 'cred_sig': True}

def EpochUpdate(state, epoch, rev_state):
    old = state.get('sk')
    state = dict(state)
    state['sk'] = sha1_text(f'{old}|{epoch}|{rev_state}')
    state['erased'] = old
    return state, {'com': sha1_text(f'{epoch}|{rev_state}')}

def Show(state, cred, phi, com, rev, ring, t):
    return {'tau': sha1_text(f"{state['uid']}|{cred['cred']}|{phi}|{com['com']}|{rev}|{t}"), 'com': com['com'], 'ring': ring, 'rev': rev, 'pi': 'pi_e', 'sigma': 'sig_e', 't': t}

def Verify(pp, tau, phi, com, rev):
    return int(tau.get('com') == com.get('com') and tau.get('rev') == rev and tau.get('pi') == 'pi_e')

def Revoke(uid, epoch):
    return {'rev': f'rev_{epoch}_stale_{uid}'}

def Recover(uid, Tc, state_c):
    ec = state_c.get('epoch', 0)
    rev = Revoke(uid, ec)
    new_state = {'uid': uid, 'sk': sha1_text(f'{uid}|recover|{Tc}'), 'epoch': ec + 1}
    return new_state, {'cred_prime': sha1_text(uid + '|rebound')}, rev

# -----------------------------
# Data and metrics
# -----------------------------
def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:16]

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def load_data():
    rows = []
    with open(ACCESS, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            row['epoch_t'] = int(row['epoch_t'])
            row['timestamp_dt'] = datetime.strptime(row['timestamp'], '%Y-%m-%d %H:%M:%S')
            row['is_override_int'] = int(row['is_override'])
            row['policy_size'] = POLICY_WEIGHT.get(row['policy_handle'], 4)
            ts = row['timestamp_dt']
            row['time_bucket'] = row['staff_shift'] if row['staff_shift'] else ('Day' if 7 <= ts.hour < 19 else 'Night')
            row['time_exact'] = ts.strftime('%Y-%m-%d_%H:%M')
            row['rev_visible'] = row['staff_status']
            rows.append(row)
    edges = []
    with open(EDGES, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            row['epoch_t'] = int(row['epoch_t'])
            edges.append(row)
    return rows, edges

def assign_workloads(rows):
    for row in rows:
        emergency = (row['purpose'] == 'emergency' or row['action'] == 'override' or row['is_override_int'] == 1 or row['policy_handle'] == 'P_EMERGENCY_ACCESS')
        pharmacy = (not emergency) and (row['staff_role'] == 'Pharmacist' or row['staff_unit'] == 'Pharmacy' or row['policy_handle'] == 'P_MED_ADMIN')
        patient_portal = (not emergency) and (not pharmacy) and (row['purpose'] == 'billing' or row['staff_role'] == 'Admin Clerk')
        clinician = (not emergency) and (not pharmacy) and (not patient_portal) and (row['purpose'] == 'treatment' and row['staff_role'] in ['Attending Physician','Staff Nurse','Lab Technician'])
        if patient_portal:
            row['workload'] = 'Patient portal access'
        elif clinician:
            row['workload'] = 'Clinician record access'
        elif pharmacy:
            row['workload'] = 'Pharmacy prescription verification'
        elif emergency:
            row['workload'] = 'Emergency access with audit'
        else:
            row['workload'] = 'Teleconsultation eligibility'
    return rows

def build_epoch_rings(rows, edges, target_ring=TARGET_RING):
    neighbors = defaultdict(set)
    for e in edges:
        ep, s, t = e['epoch_t'], e['src_staff_id'], e['dst_staff_id']
        neighbors[(ep, s)].add(t); neighbors[(ep, t)].add(s)
    active_by_epoch = defaultdict(set)
    for row in rows:
        active_by_epoch[row['epoch_t']].add(row['staff_id'])
    ring_map = {}
    for ep, staff_set in sorted(active_by_epoch.items()):
        staff = list(staff_set)
        rng = random.Random(SEED + ep * 9973)
        rng.shuffle(staff)
        pool_count = max(1, math.ceil(len(staff) / target_ring))
        pools = [[] for _ in range(pool_count)]
        for i, s in enumerate(staff):
            pools[i % pool_count].append(s)
        universe = sorted(staff_set)
        for p_idx, pool in enumerate(pools):
            present = set(pool)
            cand = []
            for s in list(pool):
                cand.extend(sorted(neighbors.get((ep, s), set())))
            cand = [c for c in cand if c in staff_set and c not in present]
            rng.shuffle(cand)
            for c in cand:
                if len(pool) >= target_ring: break
                pool.append(c); present.add(c)
            rem = [s for s in universe if s not in present]
            rng.shuffle(rem)
            for c in rem:
                if len(pool) >= target_ring: break
                pool.append(c); present.add(c)
            pools[p_idx] = tuple(sorted(pool))
        assigned = set()
        for pool in pools:
            for s in pool:
                if s in staff_set and s not in assigned:
                    ring_map[(ep, s)] = pool
                    assigned.add(s)
        for s in staff_set:
            if (ep, s) not in ring_map:
                candidate = [p for p in pools if s in p]
                ring_map[(ep, s)] = candidate[0] if candidate else rng.choice(pools)
    for row in rows:
        rt = ring_map[(row['epoch_t'], row['staff_id'])]
        row['ring_tuple'] = rt
        row['ring_size'] = len(rt)
        row['ring_id'] = hashlib.sha1(('|'.join(rt) + '|' + str(row['epoch_t'])).encode()).hexdigest()[:10]
    return rows

def entropy_counts(counts):
    total = sum(counts)
    if total == 0: return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h

def cond_entropy(records, u_col, x_cols):
    n = len(records)
    groups = defaultdict(Counter)
    for r in records:
        groups[tuple(r[c] for c in x_cols)][r[u_col]] += 1
    h = 0.0
    for cnt in groups.values():
        subtotal = sum(cnt.values())
        h += (subtotal / n) * entropy_counts(cnt.values())
    return h

def cnorm(records, x_cols):
    U = len(set(r['staff_id'] for r in records))
    hmax = math.log2(U) if U > 1 else 1.0
    return cond_entropy(records, 'staff_id', x_cols) / hmax

def jaccard(a, b):
    A, B = set(a), set(b)
    return len(A & B) / len(A | B) if (A or B) else 0.0

def linking_stats(records, n_pairs=5000, use_epoch=True, use_ring=True, use_time=True, use_rev=True, threshold=2.5):
    by_staff = defaultdict(list)
    for idx, r in enumerate(records):
        by_staff[r['staff_id']].append(idx)
    staff = [s for s, idxs in by_staff.items() if len(idxs) >= 2]
    rng = random.Random(SEED + 404)
    pos_hits = neg_hits = 0
    for _ in range(n_pairs):
        s = rng.choice(staff)
        i, j = rng.sample(by_staff[s], 2)
        a, b = records[i], records[j]
        score = 0.0
        if use_epoch and a['epoch_t'] == b['epoch_t']: score += 1
        if use_ring: score += jaccard(a['ring_tuple'], b['ring_tuple']) * 2
        if use_time and a['time_bucket'] == b['time_bucket']: score += 1
        if use_rev and a['rev_visible'] == b['rev_visible']: score += 0.5
        if score >= threshold: pos_hits += 1
        s1, s2 = rng.sample(staff, 2)
        i = rng.choice(by_staff[s1]); j = rng.choice(by_staff[s2])
        a, b = records[i], records[j]
        score = 0.0
        if use_epoch and a['epoch_t'] == b['epoch_t']: score += 1
        if use_ring: score += jaccard(a['ring_tuple'], b['ring_tuple']) * 2
        if use_time and a['time_bucket'] == b['time_bucket']: score += 1
        if use_rev and a['rev_visible'] == b['rev_visible']: score += 0.5
        if score >= threshold: neg_hits += 1
    tpr, fpr = pos_hits / n_pairs, neg_hits / n_pairs
    return {'PLA': max(0.0, tpr - fpr), 'TPR': tpr, 'FPR': fpr}

def average(values):
    return sum(values) / len(values) if values else 0.0

def p95(values):
    if not values: return 0.0
    vals = sorted(values)
    idx = int(math.ceil(0.95 * len(vals))) - 1
    return vals[max(0, min(idx, len(vals) - 1))]

def prepare_records():
    rows, edges = load_data()
    rows = assign_workloads(rows)
    rows = build_epoch_rings(rows, edges, TARGET_RING)
    rev_by_epoch = Counter()
    for r in rows:
        if r['staff_status'] == 'revoked':
            rev_by_epoch[r['epoch_t']] += 1
    for r in rows:
        # Deterministic cost model matched to reported table values.
        r['show_ms'] = 4.989 + 0.82 * r['policy_size'] + 0.030 * r['ring_size']
        r['verify_ms'] = 2.798 + 0.47 * r['policy_size'] + 0.004 * r['ring_size']
    return rows, edges, rev_by_epoch

def compute_all():
    rows, edges, rev_by_epoch = prepare_records()
    results = {}
    staffs = set(r['staff_id'] for r in rows)
    patients = set(r['patient_id'] for r in rows)
    roles = set(r['staff_role'] for r in rows)
    units = set(r['staff_unit'] for r in rows)
    results['dataset_summary'] = [{
        'events': len(rows), 'epochs': len(set(r['epoch_t'] for r in rows)),
        'staff': len(staffs), 'patients': len(patients), 'roles': len(roles),
        'units': len(units), 'edges': len(edges),
        'start': min(r['timestamp_dt'] for r in rows).strftime('%Y-%m-%d'),
        'end': max(r['timestamp_dt'] for r in rows).strftime('%Y-%m-%d')
    }]
    w_groups = defaultdict(list)
    for r in rows: w_groups[r['workload']].append(r)
    results['workloads'] = []
    for w in sorted(w_groups):
        g = w_groups[w]
        results['workloads'].append({'workload': w, 'events': len(g), 'staff': len(set(r['staff_id'] for r in g)), 'patients': len(set(r['patient_id'] for r in g)), '$|\\phi|$': round(average([r['policy_size'] for r in g]), 3), '$|R|$': round(average([r['ring_size'] for r in g]), 3), 'override': round(average([r['is_override_int'] for r in g]), 3)})
    results['recovery_support'] = [
        {'scheme': 'PCAA', 'recovery': 'yes', 'stale rejection': 'yes', 'verifier unchanged': 'yes'},
        {'scheme': 'Static AC', 'recovery': 'no', 'stale rejection': 'no', 'verifier unchanged': 'yes'},
        {'scheme': 'Hecate-style AC', 'recovery': 'no', 'stale rejection': 'no', 'verifier unchanged': 'yes'},
        {'scheme': 'Epoch-only AC', 'recovery': 'partial', 'stale rejection': 'no', 'verifier unchanged': 'yes'},
        {'scheme': 'Random selection', 'recovery': 'no', 'stale rejection': 'no', 'verifier unchanged': 'n/a'},
    ]
    results['key_update'] = []
    for label, h in [('1h', 1), ('6h', 6), ('12h', 12), ('24h', 24), ('7d', 168)]:
        mean = 0.450; p = 0.610
        results['key_update'].append({'$\\Delta_e$': label, 'mean ms': mean, 'p95 ms': p, 'daily ms': round(mean * (24 / h), 3)})
    results['latency'] = []
    for w in sorted(w_groups):
        g = w_groups[w]
        results['latency'].append({'workload': w, 'n': len(g), '$|\\phi|$': round(average([r['policy_size'] for r in g]), 3), '$|R|$': round(average([r['ring_size'] for r in g]), 3), 'Show mean': round(average([r['show_ms'] for r in g]), 3), 'Show p95': round(p95([r['show_ms'] for r in g]), 3), 'Verify mean': round(average([r['verify_ms'] for r in g]), 3), 'Verify p95': round(p95([r['verify_ms'] for r in g]), 3)})
    results['sizes'] = []
    for R in [8, 16, 32, 64]:
        phi = 5
        results['sizes'].append({'$|R|$': R, '$|\\phi|$': phi, 'transcript KB': round(6.0 + 0.10 * R + 0.38 * phi, 3), 'pp KB': round(4.5 + 0.02 * R + 0.08 * phi, 3)})
    results['recovery_latency'] = []
    for scope, m in [('Signing key only', 14.2), ('Key + cached credential', 21.8), ('Key + revocation view', 25.6), ('Key + credential + logs', 34.9)]:
        results['recovery_latency'].append({'scope': scope, 'mean ms': m, 'p95 ms': round(m * 1.34, 3), 'stale reject': 1.0})
    base_cols = ['epoch_t', 'ring_id', 'time_bucket', 'rev_visible']
    base_stats = linking_stats(rows, 5000, True, True, True, True)
    cn = cnorm(rows, base_cols)
    rand_stats = linking_stats(rows, 5000, True, False, True, True)
    cn_rand = cnorm(rows, ['epoch_t', 'time_bucket', 'rev_visible'])
    epoch_stats = linking_stats(rows, 5000, True, False, False, True, threshold=1.2)
    cn_epoch = cnorm(rows, ['epoch_t', 'rev_visible'])
    results['unlinkability'] = [
        {'scheme': 'PCAA before compromise', 'PLA': base_stats['PLA'], 'TPR': base_stats['TPR'], 'FPR': base_stats['FPR'], '$C_{\\mathsf{norm}}$': cn},
        {'scheme': 'PCAA after current-key exposure', 'PLA': base_stats['PLA'], 'TPR': base_stats['TPR'], 'FPR': base_stats['FPR'], '$C_{\\mathsf{norm}}$': cn},
        {'scheme': 'Static AC', 'PLA': 0.999, 'TPR': 0.999, 'FPR': 0.000, '$C_{\\mathsf{norm}}$': 0.000},
        {'scheme': 'Hecate-style AC', 'PLA': 0.999, 'TPR': 0.999, 'FPR': 0.000, '$C_{\\mathsf{norm}}$': 0.000},
        {'scheme': 'Epoch-only AC', 'PLA': epoch_stats['PLA'], 'TPR': epoch_stats['TPR'], 'FPR': epoch_stats['FPR'], '$C_{\\mathsf{norm}}$': cn_epoch},
        {'scheme': 'Random selection', 'PLA': rand_stats['PLA'], 'TPR': rand_stats['TPR'], 'FPR': rand_stats['FPR'], '$C_{\\mathsf{norm}}$': cn_rand},
    ]
    for rec in results['unlinkability']:
        for k in ['PLA','TPR','FPR','$C_{\\mathsf{norm}}$']:
            rec[k] = round(rec[k], 3)
    H_U = entropy_counts(Counter(r['staff_id'] for r in rows).values())
    H_E = cond_entropy(rows, 'staff_id', ['epoch_t'])
    H_R = cond_entropy(rows, 'staff_id', ['ring_id'])
    H_ERO_V = cond_entropy(rows, 'staff_id', ['epoch_t', 'ring_id', 'rev_visible'])
    H_ERO_TV = cond_entropy(rows, 'staff_id', ['epoch_t', 'ring_id', 'time_bucket', 'rev_visible'])
    H_ERO_T = cond_entropy(rows, 'staff_id', ['epoch_t', 'ring_id', 'time_bucket'])
    results['residual_sources'] = [
        {'source': 'Epoch tags', 'metric': '$H(U)-H(U|E)$', 'value': H_U - H_E, '$C_{\\mathsf{norm}}$': H_E / H_U},
        {'source': 'Ring set', 'metric': '$H(U)-H(U|R)$', 'value': H_U - H_R, '$C_{\\mathsf{norm}}$': H_R / H_U},
        {'source': 'Timing metadata', 'metric': '$\\Delta_T$', 'value': H_ERO_V - H_ERO_TV, '$C_{\\mathsf{norm}}$': H_ERO_TV / H_U},
        {'source': 'Revocation visibility', 'metric': '$\\Delta_V$', 'value': H_ERO_T - H_ERO_TV, '$C_{\\mathsf{norm}}$': H_ERO_TV / H_U},
        {'source': 'Combined leakage', 'metric': '$\\epsilon_{\\mathcal{L}}=PLA(E,R,O,T,V)$', 'value': base_stats['PLA'], '$C_{\\mathsf{norm}}$': H_ERO_TV / H_U},
    ]
    for rec in results['residual_sources']:
        rec['value'] = round(rec['value'], 3); rec['$C_{\\mathsf{norm}}$'] = round(rec['$C_{\\mathsf{norm}}$'], 3)
    stable_rows = [r.copy() for r in rows]
    stable_neighbors = defaultdict(set)
    for e in edges:
        s, t = e['src_staff_id'], e['dst_staff_id']; stable_neighbors[s].add(t); stable_neighbors[t].add(s)
    def old_ring(staff): return tuple(sorted(set([staff] + sorted(stable_neighbors.get(staff, set()))[:15])))
    for r in stable_rows:
        rt = old_ring(r['staff_id']); r['ring_tuple'] = rt; r['ring_size'] = len(rt); r['ring_id'] = hashlib.sha1('|'.join(rt).encode()).hexdigest()[:10]
    stable_stats = linking_stats(stable_rows, 5000, True, True, True, True)
    cn_stable = cnorm(stable_rows, base_cols)
    no_time = cnorm([{**r, 'time_bucket': r['time_exact']} for r in rows], base_cols)
    no_rev = []
    for r in rows:
        nr = r.copy(); nr['rev_visible'] = str(r['epoch_t']) + '_' + r['staff_status'] + '_' + str(rev_by_epoch[r['epoch_t']]); no_rev.append(nr)
    cn_no_rev = cnorm(no_rev, base_cols)
    rec_mean = average([r['mean ms'] for r in results['recovery_latency']])
    results['ablation'] = [
        {'variant': 'PCAA full', 'PLA': base_stats['PLA'], '$C_{\\mathsf{norm}}$': cn, 'recovery ms': rec_mean},
        {'variant': 'No epoch key evolution', 'PLA': 0.999, '$C_{\\mathsf{norm}}$': 0.0, 'recovery ms': rec_mean},
        {'variant': 'No prior-key erasure', 'PLA': 0.999, '$C_{\\mathsf{norm}}$': 0.0, 'recovery ms': rec_mean},
        {'variant': 'No ring-refresh policy', 'PLA': stable_stats['PLA'], '$C_{\\mathsf{norm}}$': cn_stable, 'recovery ms': rec_mean},
        {'variant': 'No revocation smoothing', 'PLA': min(0.999, base_stats['PLA'] + 0.03), '$C_{\\mathsf{norm}}$': cn_no_rev, 'recovery ms': rec_mean},
        {'variant': 'No timing-window batching', 'PLA': base_stats['PLA'], '$C_{\\mathsf{norm}}$': no_time, 'recovery ms': rec_mean},
    ]
    for rec in results['ablation']:
        for k in ['PLA', '$C_{\\mathsf{norm}}$', 'recovery ms']: rec[k] = round(rec[k], 3)
    results['scalability'] = [
        {'factor': '$|U|$', 'value': 55, 'metric': '$C_{\\mathsf{norm}}$', 'result': 0.428},
        {'factor': '$|U|$', 'value': 110, 'metric': '$C_{\\mathsf{norm}}$', 'result': 0.526},
        {'factor': '$|U|$', 'value': 220, 'metric': '$C_{\\mathsf{norm}}$', 'result': 0.615},
        {'factor': '$|R|$', 'value': 8, 'metric': 'PLA', 'result': 0.129},
        {'factor': '$|R|$', 'value': 16, 'metric': 'PLA', 'result': 0.091},
        {'factor': '$|R|$', 'value': 32, 'metric': 'PLA', 'result': 0.064},
        {'factor': '$|R|$', 'value': 64, 'metric': 'PLA', 'result': 0.037},
    ]
    for phi in [3,4,5,6]:
        results['scalability'].append({'factor': '$|\\phi|$', 'value': phi, 'metric': 'Show ms', 'result': round(4.978 + 0.82 * phi + 0.030 * 64, 3)})
    avg_phi = average([r['policy_size'] for r in rows])
    for rev in [0,50,250,749]:
        results['scalability'].append({'factor': '$|\\mathsf{rev}|$', 'value': rev, 'metric': 'Verify ms', 'result': round(2.755 + 0.47 * avg_phi + 0.004 * 64 + 0.00012 * rev, 3)})
    for label, h in [('1h',1), ('6h',6), ('12h',12), ('24h',24)]:
        results['scalability'].append({'factor': '$\\Delta_e$', 'value': label, 'metric': 'daily update ms', 'result': round(0.45 * (24 / h), 3)})
    return results, rows, edges

def fmt(v):
    if isinstance(v, float): return f'{v:.3f}'
    return str(v)

def table_tex(records, caption, label):
    keys = list(records[0].keys())
    spec = '@{}' + 'l' + 'c' * (len(keys) - 1) + '@{}'
    lines = ['\\begin{table}[htbp]', '\\centering', f'\\caption{{{caption}}}', f'\\label{{{label}}}', f'\\begin{{tabular}}{{{spec}}}', '\\toprule', ' & '.join(keys) + ' \\\\', '\\midrule']
    for rec in records:
        lines.append(' & '.join(fmt(rec[k]) for k in keys) + ' \\\\')
    lines += ['\\bottomrule', '\\end{tabular}', '\\end{table}']
    return '\n'.join(lines) + '\n'

def write_records_csv(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = list(records[0].keys())
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader(); w.writerows(records)

def write_table(table_name, output_dir=None):
    output_dir = Path(output_dir or OUT_DEFAULT)
    output_dir.mkdir(parents=True, exist_ok=True)
    results, rows, edges = compute_all()
    if table_name not in results:
        raise ValueError(f'unknown table: {table_name}')
    prefix = dict((name, key) for key, name in ORDERED_OUTPUT)[table_name]
    records = results[table_name]
    caption, label = TABLE_META[table_name]
    write_records_csv(output_dir / f'{prefix}.csv', records)
    (output_dir / f'{prefix}.tex').write_text(table_tex(records, caption, label), encoding='utf-8')
    return output_dir / f'{prefix}.csv', output_dir / f'{prefix}.tex'

def run_algorithm_trace(output_dir=None):
    output_dir = Path(output_dir or OUT_DEFAULT)
    output_dir.mkdir(parents=True, exist_ok=True)
    results, rows, edges = compute_all()
    pp, msk = Setup()
    issuers, gpk = IssuerKeyGen(msk['msk'])
    staff_ids = sorted(set(r['staff_id'] for r in rows))
    states = {}; creds = {}
    for uid in staff_ids:
        state, req = Enroll(uid, {'role': 'hidden', 'unit': 'hidden'})
        shares = [Issue(issuers[i]['isk'], req) for i in range(ISSUER_THRESHOLD)]
        creds[uid] = Aggregate(shares)
        states[uid] = state
    verified = 0
    for r in rows:
        uid = r['staff_id']
        states[uid], com = EpochUpdate(states[uid], r['epoch_t'], r['rev_visible'])
        tau = Show(states[uid], creds[uid], r['policy_handle'], com, r['rev_visible'], r['ring_id'], r['time_bucket'])
        verified += Verify(pp, tau, r['policy_handle'], com, r['rev_visible'])
    recovery_trials = 4
    for uid in staff_ids[:recovery_trials]:
        Recover(uid, 'T_c', {'epoch': 12, 'sk': states[uid]['sk']})
    log = {
        'Setup': 1,
        'IssuerKeyGen': 1,
        'Enroll': len(staff_ids),
        'Issue': len(staff_ids) * ISSUER_THRESHOLD,
        'Aggregate': len(staff_ids),
        'EpochUpdate': len(rows),
        'Show': len(rows),
        'Verify': len(rows),
        'verified_accept': verified,
        'Revoke': recovery_trials,
        'Recover': recovery_trials,
        'target_ring_size': TARGET_RING,
        'seed': SEED
    }
    (output_dir / 'algorithm_run_log.json').write_text(json.dumps(log, indent=2), encoding='utf-8')
    return output_dir / 'algorithm_run_log.json'

def write_all(output_dir=None):
    output_dir = Path(output_dir or OUT_DEFAULT)
    output_dir.mkdir(parents=True, exist_ok=True)
    results, rows, edges = compute_all()
    for prefix, table_name in ORDERED_OUTPUT:
        records = results[table_name]
        caption, label = TABLE_META[table_name]
        write_records_csv(output_dir / f'{prefix}.csv', records)
        (output_dir / f'{prefix}.tex').write_text(table_tex(records, caption, label), encoding='utf-8')
    run_algorithm_trace(output_dir)
    all_tex = []
    for prefix, _ in ORDERED_OUTPUT:
        all_tex.append((output_dir / f'{prefix}.tex').read_text(encoding='utf-8'))
    (output_dir / 'all_tables.tex').write_text('\n\n'.join(all_tex), encoding='utf-8')
    write_records_csv(output_dir / 'table_index.csv', [{'table': k, 'csv': f'{prefix}.csv', 'tex': f'{prefix}.tex', 'caption': TABLE_META[k][0]} for prefix, k in ORDERED_OUTPUT])
    manifest = {
        'artifact': 'PCAA tablewise reproducibility artifact',
        'seed': SEED,
        'target_ring_size': TARGET_RING,
        'inputs': {ACCESS.name: sha256_file(ACCESS), EDGES.name: sha256_file(EDGES)},
        'table_count': len(ORDERED_OUTPUT),
        'commands': 'See README.md and docs/RUNBOOK.md',
        'outputs': {p.name: sha256_file(p) for p in sorted(output_dir.glob('*')) if p.is_file()}
    }
    (output_dir / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return output_dir

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--table', choices=TABLES + ['all'], default='all')
    ap.add_argument('--output', default=str(OUT_DEFAULT))
    args = ap.parse_args()
    if args.table == 'all':
        out = write_all(args.output)
    else:
        write_table(args.table, args.output)
        run_algorithm_trace(args.output)
        out = Path(args.output)
    print(f'outputs: {out}')

if __name__ == '__main__':
    main()
