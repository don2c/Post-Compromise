# Runbook

## Full reproduction

```bash
python scripts/run_all.py
```

Expected output directory:

```text
output/
```

## Individual commands

| Table | Command |
|---|---|
| Dataset summary | `python scripts/tables/table_01_dataset_summary.py` |
| Workloads | `python scripts/tables/table_02_workloads.py` |
| Recovery support | `python scripts/tables/table_03_recovery_support.py` |
| Key update | `python scripts/tables/table_04_key_update.py` |
| Latency | `python scripts/tables/table_05_latency.py` |
| Size | `python scripts/tables/table_06_sizes.py` |
| Recovery latency | `python scripts/tables/table_07_recovery_latency.py` |
| Unlinkability | `python scripts/tables/table_08_unlinkability.py` |
| Residual sources | `python scripts/tables/table_09_residual_sources.py` |
| Ablation | `python scripts/tables/table_10_ablation.py` |
| Scalability | `python scripts/tables/table_11_scalability.py` |

## Verification

After a full run, inspect:

```text
output/MANIFEST.json
output/algorithm_run_log.json
output/table_index.csv
```

`MANIFEST.json` records input and output hashes. The manifest does not hash
itself, so repeated runs remain stable.
