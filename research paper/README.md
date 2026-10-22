# Temporal NIDS research: dataset audit stage

This repository is a reproducible audit of the **CNS2022 improved CIC-IDS-2017 and CSE-CIC-IDS-2018** releases (Liu, Engelen et al., IEEE CNS 2022), compared with the original releases. It is the foundation for research on temporal network-state modelling and early attack prediction.

- Work order: `CIC_IDS_Research_Plan_and_Claude_Prompt.md`.
- Progress: `reports/WORK_LOG.md`.
- Start reading at `reports/dataset_audit_report.md`.

## Status

| Phase | Status |
|---|---|
| 0 Reconnaissance | done |
| 1 Inventory and provenance (+1b acquisition) | done |
| 2 Schema and labels | done |
| 3 Integrity audit | done |
| 4 Original versus improved | done |
| 5 Temporal feasibility | done |
| 6 Leakage and evaluation design | done (protocol PROPOSED; `reports/evaluation_protocol.md`) |
| 7 Research questions and literature | done: scoping search plus a systematic citation search (`reports/literature_review.md` §5). 6 full texts still need to be read by hand. |
| Self-review (before Phase 8) | done: `reports/self_review.md`. 17/17 independent checks agree, 32/32 report claims match the data. |
| 8 Baselines and modelling | **not started: requires the user's review of the audit and protocol** |

## Layout (details in `reports/project_layout.md`)

```text
CICIDS2017_improved.zip, CSECICIDS2018_improved.zip   downloaded archives (immutable)
data/raw_improved/{CIC-IDS-2017,CSE-CIC-IDS-2018}/    extracted, hash-verified, read-only  (junction -> C:\nids_data\raw_improved)
data/raw_original/{CIC-IDS-2017,CSE-CIC-IDS-2018}/    copied originals, hash-verified, read-only (junction -> C:\nids_data\raw_original)
data/manifests/       inventory, checksums, acquisition/verification, encoding, S3-ETag check
configs/              datasets.yaml, data_audit.yaml, label_family_map.yaml,
                      evaluation_protocol.yaml, experiment_matrix.yaml
src/audit/            audit code (below)
tests/                unit tests on synthetic data only
notebooks/01-06       thin, executed notebooks over the saved outputs
results/audit/        all audit tables (CSV/JSON) and figures/
reports/              phase reports, WORK_LOG.md
references/           CNS2022 labelling code (not executed), release-site snapshot
logs/                 per-tool logs; pipeline_runs.log (step, rc, seconds)
environment/          Python and package versions
```

## Reproduce

Run from the project root with the installed Python 3.14. Scripts that read downloaded data are run with `-I` (isolated mode).

```text
# Phase 1: inventory, checksums, acquisition
python -I src/audit/inventory.py scan [--overwrite]
python -I src/audit/inventory.py hash --target CICIDS2017_improved.zip --members
python -I src/audit/inventory.py hash --target CSECICIDS2018_improved.zip --members
python -I src/audit/acquire.py extract --archive CICIDS2017_improved.zip   --dest data/raw_improved/CIC-IDS-2017
python -I src/audit/acquire.py extract --archive CSECICIDS2018_improved.zip --dest data/raw_improved/CSE-CIC-IDS-2018
python -I src/audit/acquire.py copy --src ../gnn/cic2017csv        --dest data/raw_original/CIC-IDS-2017     --pattern "*.csv"
python -I src/audit/acquire.py copy --src ../research_P1/data/01_raw --dest data/raw_original/CSE-CIC-IDS-2018 --pattern "*.csv"
python -I src/audit/acquire.py verify
python -I src/audit/s3_etag_check.py                 # original 2018 vs AWS S3 (HEAD requests only)
python -I src/audit/labelling_windows.py             # static parse of the authors' labelling rules
python -I src/audit/encoding.py check                # UTF-8 validity and line endings for all 33 CSVs

# Phases 2, 3, 5, 6 (full scans; stops at the first failing step; resume with --from <step>)
python -I src/audit/run_all.py

# Phase 4 comparison, then the findings tables
python -I src/audit/compare.py matching|families|features [--overwrite]
python -I src/audit/report.py identical|phase3|phase6 [--overwrite]
python -I src/audit/leakage.py splits [--overwrite]  # needs configs/evaluation_protocol.yaml
python -I src/audit/leakage.py conflicts [--overwrite]  # label composition of conflict groups

# Self-review (independent re-computation; report-vs-data claim check)
python -I src/audit/self_review.py [--overwrite]     # streams ~45 GB with pyarrow; no DuckDB, no caches
python -I src/audit/check_claims.py [--overwrite]

# Literature: forward citations of CNS2022 + Engelen 2021, keyword screen, logged OpenAlex queries
python -I src/lit/citation_search.py fetch|screen|search [--overwrite]

# Notebooks and tests
python -I src/audit/make_notebooks.py --execute [--overwrite]
python -m pytest -q
```

**Resources.** The full pipeline needs about 45 GB of disk for the raw CSVs (kept in `C:\nids_data`, outside OneDrive, behind junctions at `data/raw_*`), plus a few GB of cache under `%TEMP%\nids_audit_cache`. DuckDB is capped at 3 GB of RAM and 10 threads (`configs/data_audit.yaml`).

## Safety rules (from the work order)

- Raw files are never modified, moved or renamed. Acquired copies are hash-verified and set read-only. Nothing is extracted over existing files.
- No package is installed or upgraded without asking. Nothing is committed or pushed. This folder is not a Git repository; `.gitignore` excludes data, PDFs and the cloned repository.
- Nothing is dropped silently. Every exclusion is counted and logged, and the audit itself repairs nothing.
- Never model inputs: labels, `Attempted Category`, `id`, `Flow ID`, IPs, source port, timestamps (except to order and aggregate), and file, day or scenario identity.
- Random row splits are diagnostic only. The primary evaluation is chronological or day-held-out, with a 130 s embargo.
- Results carry the labels VERIFIED, DOCUMENTED, HYPOTHESIS or UNRESOLVED. Existing outputs are not overwritten unless `--overwrite` is given explicitly, and every such run is logged.
