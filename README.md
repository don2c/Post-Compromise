# PCAA Tablewise Reproducibility Artifact

Self-contained artifact for PCAA experimental tables.

## Data
- `raw_data/prime_ring_ehealth_access_log.csv`
- `raw_data/prime_ring_ehealth_staff_graph_edges.csv`

## Run all tables
```bash
python scripts/run_all.py
```
All outputs are written to `output/`.

## Run one table
```bash
python scripts/tables/table_01_dataset_summary.py
python scripts/tables/table_02_workloads.py
python scripts/tables/table_03_recovery_support.py
python scripts/tables/table_04_key_update.py
python scripts/tables/table_05_latency.py
python scripts/tables/table_06_sizes.py
python scripts/tables/table_07_recovery_latency.py
python scripts/tables/table_08_unlinkability.py
python scripts/tables/table_09_residual_sources.py
python scripts/tables/table_10_ablation.py
python scripts/tables/table_11_scalability.py
```
Each command writes its CSV and LaTeX table to `output/`.

## Algorithms executed
`pcaa_core.py` contains the trace-replay implementations of `Setup`, `IssuerKeyGen`, `Enroll`, `Issue`, `Aggregate`, `EpochUpdate`, `Show`, `Verify`, `Revoke`, and `Recover`. `algorithm_run_log.json` records call counts.

## Ring policy
Target ring size is `|R|=64`. Rings are epoch-rotating shared pools. Graph neighbors are used before active decoy fill. This avoids staff-local ego-ring leakage.

## Outputs
- `output/*.csv`: numeric tables
- `output/*.tex`: three-line LaTeX tables
- `output/all_tables.tex`: all LaTeX tables
- `output/table_index.csv`: output map
- `output/algorithm_run_log.json`: algorithm counts
- `output/MANIFEST.json`: input and output hashes

  ## Full reproduction
Run from artifact root:
```bash
python scripts/run_all.py
```
Expected folder:
```text
output/
```

## Table commands
| Table | Command | Output files |
|---|---|---|
| Dataset summary | `python scripts/tables/table_01_dataset_summary.py` | `01_dataset_summary.csv`, `01_dataset_summary.tex` |
| Workloads | `python scripts/tables/table_02_workloads.py` | `02_workloads.csv`, `02_workloads.tex` |
| Recovery support | `python scripts/tables/table_03_recovery_support.py` | `03_recovery_support.csv`, `03_recovery_support.tex` |
| Key update | `python scripts/tables/table_04_key_update.py` | `04_key_update.csv`, `04_key_update.tex` |
| Latency | `python scripts/tables/table_05_latency.py` | `05_latency.csv`, `05_latency.tex` |
| Size | `python scripts/tables/table_06_sizes.py` | `06_sizes.csv`, `06_sizes.tex` |
| Recovery latency | `python scripts/tables/table_07_recovery_latency.py` | `07_recovery_latency.csv`, `07_recovery_latency.tex` |
| Unlinkability | `python scripts/tables/table_08_unlinkability.py` | `08_unlinkability.csv`, `08_unlinkability.tex` |
| Residual sources | `python scripts/tables/table_09_residual_sources.py` | `09_residual_sources.csv`, `09_residual_sources.tex` |
| Ablation | `python scripts/tables/table_10_ablation.py` | `10_ablation.csv`, `10_ablation.tex` |
| Scalability | `python scripts/tables/table_11_scalability.py` | `11_scalability.csv`, `11_scalability.tex` |

## Algorithm path
Each table script imports `scripts/pcaa_core.py`. The core module loads the two datasets, assigns workloads, builds epoch-rotating rings, executes the PCAA trace functions, computes metrics, and writes table files.

