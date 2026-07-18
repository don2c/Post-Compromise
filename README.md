# PCAA-Cred Reproducibility Artifact

This package reproduces the experimental tables for the PCAA-Cred manuscript.
It contains the synthetic trace, staff graph, experiment source code, table scripts,
and regenerated CSV/LaTeX outputs.

## Directory layout

```text
raw_data/
  prime_ring_ehealth_access_log.csv
  prime_ring_ehealth_staff_graph_edges.csv
scripts/
  pcaa_core.py
  run_all.py
  tables/table_01_dataset_summary.py
  tables/table_02_workloads.py
  tables/table_03_recovery_support.py
  tables/table_04_key_update.py
  tables/table_05_latency.py
  tables/table_06_sizes.py
  tables/table_07_recovery_latency.py
  tables/table_08_unlinkability.py
  tables/table_09_residual_sources.py
  tables/table_10_ablation.py
  tables/table_11_scalability.py
output/
  regenerated CSV and LaTeX tables
  all_tables.tex
  table_index.csv
  algorithm_run_log.json
  MANIFEST.json
docs/
  RUNBOOK.md
  METHODS.md
  DATA_AVAILABILITY.md
```

## Reproduce all results

Run from the artifact root:

```bash
python scripts/run_all.py
```

This rewrites `output/` and regenerates all tables.

## Reproduce one table

```bash
python scripts/tables/table_08_unlinkability.py
```

Replace the script number to regenerate another table.

## What is implemented

The code implements the reference state machine used in the paper. It covers
workload replay, epoch-ring construction, exposure classes, recovery actions,
leakage extraction, cost-model tables, and table generation. It is not a
production cryptographic library.

## Synthetic trace

The trace has 45,000 authorisation events, 12 epochs, 220 staff accounts,
3,500 patients, five roles, six units, five purposes, and five workflows.
The data are synthetic and contain no observed hospital access log.
