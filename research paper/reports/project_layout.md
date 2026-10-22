# Project layout

Project root: `research_paper/`. It is the only project root. All paths here are relative to it. Last updated 2026-10-19, after Phases 0–7.

## Layout and status

| Path | Contents | Status |
|---|---|---|
| `CICIDS2017_improved.zip`, `CSECICIDS2018_improved.zip` | Downloaded archives (immutable) | Raw input. SHA-256 recorded; size matches the server. |
| `data/raw_improved/CIC-IDS-2017/` (5 CSV, 1.15 GB) | Extracted from the 2017 zip | Each file matches its archive-member SHA-256. Read-only. |
| `data/raw_improved/CSE-CIC-IDS-2018/` (10 CSV, 36.0 GB) | Extracted from the 2018 zip | Same checks as above. Read-only. |
| `data/raw_original/CIC-IDS-2017/` (8 CSV, 1.2 GB) | Copied from `../gnn/cic2017csv/` with your permission | Copy verified by SHA-256; source mtime preserved. Read-only. |
| `data/raw_original/CSE-CIC-IDS-2018/` (10 CSV, 6.9 GB) | Copied from `../research_P1/data/01_raw/` | Copy verified, and identical to the official AWS S3 objects (multipart ETag). Read-only. |
| `data/manifests/` | Inventory, checksums, acquisition, verification, encoding, transcoding, timeline-cache and S3-ETag manifests | Generated |
| `data/processed/` | Not created | Deferred until the audit is reviewed (Phase 8) |
| `references/CNS2022_Code/` | The authors' labelling and experiment code, git commit `f0ce502` | Cloned for reference and never executed. Ignored by git. |
| `references/release_site_snapshot_2026-10-19/` | Snapshot of the release web pages, with `SHA256SUMS.txt` | Provenance evidence |
| `configs/` | `datasets.yaml` (raw-input registry), `data_audit.yaml` (roles, semantics, rules, DuckDB limits), `label_family_map.yaml`, `evaluation_protocol.yaml`, `experiment_matrix.yaml` | |
| `src/audit/` | All audit code (see README) | Implemented and executed. Unit-tested where noted. |
| `tests/` | Unit tests on synthetic data only | Run with `python -m pytest -q` |
| `notebooks/01–06_*.ipynb` | Thin notebooks over the saved outputs, each with an independent re-check | Generated and executed by `src/audit/make_notebooks.py --execute` |
| `results/audit/` | Every audit table and JSON, plus `figures/`; `self_review_checks.csv`, `report_claims_check.csv` | Generated |
| `results/literature/` | Screened citing works, keyword-search hits, manual screening decisions | Generated + manual decisions |
| `references/literature_search_2026-10-19/` | Raw OpenAlex / Semantic Scholar responses and `query_log.csv` | Search evidence |
| `study/` | Papers for the study guide, in step folders, with `README.md` (reading and printing order) and `download_log.csv` | Downloaded, open sources only; PDFs are ignored by git |
| `reports/` | Phase reports, `WORK_LOG.md`, this file | |
| `logs/` | One log per tool, plus `pipeline_runs.log` (step, rc, seconds) | |
| `environment/` | Interpreter and package versions | |

## Caches outside the project

Path: `%TEMP%\nids_audit_cache`. These caches are disposable and can be regenerated.

| Cache | What | Why it is outside the project |
|---|---|---|
| `utf8/` | Two read copies: the cp1252 → UTF-8 transcode of the original 2017 web-attack file, and the original 2018 `Thuesday` file with CRLF normalised to LF | DuckDB cannot read these files correctly as they are. Every cache file is hash-checked against `data/manifests/encoding_transcode_manifest.csv`. |
| `timeline/` | One Parquet file per CSV (row number, id, timestamp, label, duration, 5-tuple) | Avoids re-parsing 45 GB of CSV for every temporal analysis. Not a model dataset. |
| `leakage_hashes.duckdb` | Per-row feature hash, timestamp and class for the improved data | Used to measure duplicates that cross candidate splits |
| `nids_audit_duckdb/`, `duckdb_tmp/` | DuckDB spill space | Keeps temporary I/O off OneDrive |

## Raw data location (OneDrive)

On 2026-10-19, at the user's request, `data/raw_improved/` and `data/raw_original/` (45.3 GB) were moved to `C:\nids_data\` on the same drive. Directory **junctions** with the old names were left in their place.

- **Why:** the project lives in a OneDrive-synced folder. Before the move, OneDrive was not running, and none of the 33 files had cloud attributes, so nothing had been uploaded.
- **Paths:** all project paths, such as `data/raw_improved/...`, still resolve through the junctions.
- **Integrity:** all 33 files were re-hashed after the move and are unchanged (`data/manifests/acquisition_verification_after_relocation.csv`).
- **Caveat:** the junctions are not portable. On another machine, extract or copy the data into `data/raw_*` again, following the README.
- **Still in the synced folder:** the two downloaded zips (10.8 GB). They were placed there before this project and were not moved.
