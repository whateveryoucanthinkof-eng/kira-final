# Work log

Status words: **implemented** = written, **executed** = run, **validated** = output checked or tests passed.

---

## 2026-10-19 · Phase 0: Reconnaissance · DONE

- **Scope.** The user limited work to `research_paper/` after one file-name-only search of the parent
  Desktop folder. Two further Desktop-wide commands were rejected and were not rerun.
- **Found.** The project held only `CICIDS2017_improved.zip`, `CSECICIDS2018_improved.zip`, the CNS 2022
  paper PDF, and the work-order `.md`. There was no Git repo, `.gitignore`, notebooks, scripts, or prior EDA in the project.
- **Environment.** CPython 3.14.3 (system), pandas 3.0.6, numpy 2.5.3, pyarrow 25.0.1, duckdb 1.5.6,
  scikit-learn 1.9.1, and Jupyter are installed. Nothing was installed.
- **Disk.** 556 GB free on C:. The project folder is OneDrive-synced.
- **Outputs.**
  - `logs/phase0_reconnaissance.txt`
  - `environment/python_environment.txt`
  - `environment/pip_freeze.txt`
  - `reports/project_layout.md`
  - `.gitignore`
  - `README.md`
  - empty folders: `data/manifests`, `src/audit`, `configs`, `results/audit`, `reports`, `logs`, `environment`, `notebooks`, `tests`
- **Raw data.** Not moved, renamed, modified, or extracted.

## 2026-10-19 · Phase 1: Inventory and provenance · DONE (awaiting user review)

**Actions and commands** (run from the project root):

1. Read the paper PDF (10 pp.).
2. Checked the release site: WebFetch of 3 pages, `curl` of the dataset index, and `curl -I` HEAD
   requests on both zips (accessed 2026-10-19).
3. Wrote `configs/datasets.yaml` (raw-input registry), `src/audit/inventory.py`, and `tests/test_inventory.py`.
4. `python -m pytest -q` returned **13 passed** (synthetic data only). Validated.
5. `python -I src/audit/inventory.py scan` returned rc 0 in under 1 s and wrote 19 inventory rows, 15 archive members, and 15 headers. Executed and validated.
6. `python -I src/audit/inventory.py hash --target CICIDS2017_improved.zip --members` returned rc 0 in 3.5 s. This was the pilot.
7. `python -I src/audit/inventory.py hash --target CSECICIDS2018_improved.zip --members` returned rc 0 in 127 s. It ran in the background after the pilot-based estimate of a few minutes.

**Outputs**
- `data/manifests/dataset_inventory.csv`
- `data/manifests/archive_contents.csv`
- `data/manifests/archive_member_headers.json`
- `data/manifests/checksums_sha256.csv` (17 rows: 2 archives and 15 members)
- `reports/dataset_provenance.md`
- `logs/phase1_inventory.log`

**Findings**
- **Downloads match the release server.** Both sizes equal the server `Content-Length` exactly. All 15
  members fully decompress with correct CRC-32 and size. **VERIFIED.**
- **2017 contents:** 5 CSVs, one per weekday, 1.15 GB uncompressed. No dates in the file names.
- **2018 contents:** 10 CSVs, dated 2018-02-14 to 2018-03-02, 36.0 GB uncompressed. Weekday tokens match the dates.
- **No documentation inside either archive.** Provenance relies on the paper and the release site.
- **Schema:** all 15 files share one identical 91-column header. It includes the fork's added features
  (RST flag counts, ICMP code/type, Total TCP Flow Time), plus `Timestamp`, `Label`, `Attempted Category`, and an undocumented `id`.
- **Release version: UNRESOLVED.** The files are dated April 2023, after the paper. The site has no
  changelog or version numbers, publishes no checksum, and states no licence.
- **UNRESOLVED:** `id` semantics; `Timestamp` semantics and timezone; the regeneration flow timeout;
  the `Attempted Category` value set; and where the original datasets and prior EDA are.

**Not done (deliberately)**
- No extraction.
- No row counts, label counts, or type inference.
- No originals read.
- No notebooks.
- No model work.

**Next (needs approval):** Phase 2 schema and label audit. See the checkpoint message for the proposed
method, cost estimate, and the decisions needed from the user.

---

## 2026-10-19 · User decisions after the Phase 1 checkpoint

| Question | Decision |
|---|---|
| Extract or stream the archives? | **Extract**, into `data/raw_improved/` inside the project. The user accepted the OneDrive implication. |
| Original data | **Copy** `../gnn/cic2017csv/` and `../research_P1/data/01_raw/` into `data/raw_original/` |
| Prior EDA | **Do not use** |
| Labelling-code repository | **Clone** CNS2022_Code |

The user then asked for the work to continue through all phases without stopping, while keeping every work-order rule. Phase 8 (modelling) is still **not** started, because the plan requires the user to review the audit first.

## 2026-10-19 · Phase 1b: Acquisition and extra provenance · DONE

- **Implemented:**
  - `src/audit/acquire.py` (extract / copy / verify; hash-on-write; `.partial` files then rename; read-only; never overwrite);
  - `tests/test_acquire.py`.
- **Executed:** extract 2017 (4 s), copy originals (18 s), extract 2018 (186 s), verify all (64 s). **33/33 files verified.** One 0-byte `.gitkeep` excluded and logged.
- **Cloned** `references/CNS2022_Code`: HEAD `f0ce502`, whose tree is identical to `7f862bf` (2023-04-27). Not executed.
- **Saved** a snapshot of the release site with SHA256SUMS.
- **Static parse** of the labelling notebooks (`src/audit/labelling_windows.py`; the AST is never executed): 121 documented rules → `results/audit/attack_windows_documented.csv`.
- **New evidence:**
  - flow timeout 120 s and activity timeout 5 s (README);
  - `id` = export row number (code);
  - Infinity/NaN rows dropped before export (code);
  - Attempted categories 0–6 defined (release pages);
  - the release matches the post-publication fix commits (dates).
- **2018 originals** verified identical to the AWS S3 objects (`src/audit/s3_etag_check.py`): 10/10 ETag matches.

**Bugs found and fixed**

| Bug | Fix |
|---|---|
| `labelling_windows.safe_value` evaluated every operator eagerly, so `a**b` hung on a huge number | Now computes only the operator used, with an exponent bound. A stray background copy of the buggy script was killed; its output file was never written, so the good output stands. |

## 2026-10-19 · Phase 2: Schema and label audit · DONE

- **Implemented:**
  - `src/audit/common.py`, `encoding.py`, `schema_labels.py`, `run_all.py`;
  - `configs/data_audit.yaml`;
  - tests in `tests/test_common.py` and `tests/test_encoding.py`.
- **Executed:** full scans of all 33 files (pipeline step `phase2_scan`, 313 s). Every file was read in strict mode, and every newline is accounted for.
- **Validated:**
  - per-file row counts equal the newline counts;
  - the Thuesday file matches an independent Python byte-level count (7,948,748 rows; 576,191 + 1,595 + 7,370,962);
  - 288,602 empty rows confirmed with plain `grep` (the user challenged this number; it was re-derived independently and the same count was found in the user's source copy).
- **Findings:** see `reports/schema_and_labels.md`.

**Bugs, pitfalls and failures along the way (all logged)**

1. **DuckDB `store_rejects`:** INTERNAL assertion → abandoned in favour of strict reads plus newline counts.
2. **Invalid UTF-8:** DuckDB fatal error → files transcoded from cp1252 in a cache.
3. **First full scan masked a crash.** It ran through `grep`, which hid a traceback, and `derive` then ran on stale output. Fixed by gating each step on exit codes (`run_all.py`).
4. **Mixed line endings:** forcing `new_line` silently dropped 600,381 rows. Caught by the newline cross-check; fixed with CRLF→LF normalisation in the cache.
5. **`TRY_CAST(… AS BIGINT)` rounds decimals:** types were wrong in the first run. Fixed with a regex-based integer test, and Phase 2 was re-run.
6. **Two hand-computed subtotals in the report were wrong** (3,042 and 3,723). Corrected to 2,340 and 3,717 by script.

## 2026-10-19 · Phase 3: Integrity audit · DONE

- **Implemented:**
  - `src/audit/integrity.py` (timeline, numeric, duplicates, timestamps);
  - `src/audit/report.py` (identical, phase3, phase6);
  - plausibility rules in `configs/data_audit.yaml`;
  - `tests/test_audit_sql.py`.
- **Executed** with `run_all.py`, gated on exit codes:

  | Step | Time |
  |---|---|
  | timeline (Parquet cache of row number, id, ts, label, duration, 5-tuple) | 239 s |
  | numeric | 307 s |
  | duplicates | 319 s |
  | timestamps | 12 s |
  | `report.py identical` | 58 s |
  | `report.py phase3` | < 1 s |

- **Validated:**
  - every attack and Attempted flow (4,359,069) lies inside a documented labelling window;
  - `id` equals the physical row number in 100% of rows;
  - integer and decimal values are hashed by value (unit test).
- **Outputs:**
  - `results/audit/findings.csv` (200 findings) and `integrity_summary.json`;
  - `missingness_by_file.csv`, `numeric_feature_summary.csv`, `plausibility_by_file.csv`;
  - `duplicates_by_file.csv`, `identical_columns.csv`;
  - `timestamp_quality.csv`, `label_window_consistency.csv`.
- **Report:** `reports/dataset_audit_report.md`.

**Bugs and failures**

1. **numeric step rc=1** (`TypeError` on NULL counts): 2018 originals lack some columns. Counts are now coerced to 0, and the step was re-run.
2. **Text hashing undercounted cross-file duplicates**, because the same number is written `0` in one file and `0.0` in another. Fixed with `hash_expr`, which casts numeric columns to DOUBLE. Duplicates, hashes and splits were re-run.
3. **Variable shadowing in `report.py`** (`o`) broke the output path. The partial write then tripped the overwrite guard (rc=2, logged). Fixed and re-run with `--overwrite`.
4. **Double counting.** Improved header-length negatives were reported both as INVALID_VALUE and as EXPORT_OVERFLOW. INVALID_VALUE now skips them.
5. **Non-data rows were counted as duplicates.** Found while writing the final report: the 288,602 empty rows (2017 original) and the 59 repeated header rows (2018 original) were inside the duplicate counts. The wrong figures were 19.15% feature-identical for 2017 original, and 59 "cross-file duplicates" for 2018 original that were in fact the header rows. Fixed:
   - `integrity.py duplicates` now counts over data rows only (`n_data_rows`) and keeps the raw figure as `*_incl_nondata`;
   - separability now excludes the header rows.

   Both steps were re-run (334 s and 320 s). Corrected: 2017 original **10.91%**; 2018 original cross-file duplicates **0**.
6. **Report wording errors** fixed by script: "8 of 10" capped files became 7 of 10; "9 files spill past midnight" became 7; "no gap over 128 s" became 130 s (the 128 s figure was the longest empty-window run); the time-order share was corrected to 30–45%.

## 2026-10-19 · Phase 4: Original versus improved · DONE

- **Implemented:** `src/audit/compare.py` (families, features, matching, summary); `configs/label_family_map.yaml`.
- **Executed:** matching (190 s, first run), families, features, summary.
- **Row matching.**
  - Key: 5-tuple plus start time at the original's resolution, with whole-hour offsets −12…12 h searched on a 5% deterministic sample.
  - Pre-stated criteria: unique ≥ 0.90 and ambiguous ≤ 0.02.
  - Only 2017 Friday PortScan meets them (0.914), so it alone gets a transition matrix.
- **Bugs:**
  1. `INTERVAL -12 HOUR` is a parser error; replaced by `to_hours(h)`.
  2. **2017 Monday matched only 0.408.** The 12-hour clock applies to all 2017 files, and Monday needs seconds in the key. With both fixed, Monday matches 0.728.
  3. **2018 originals were wrongly reported as a 24-hour clock.** Their hour histograms contain only hours 1–12, like 2017. `compare.py` now detects the 12-hour clock from the data (`timestamp_quality.csv`), and matching was re-run (184 s). The 2018 Tuesday file now matches **0.783** uniquely (was 0.419), still below 0.90. The offset scan separates −4 h (0.783) from +8 h (0.352). The 2017 results are unchanged.
- **Report:** `reports/original_vs_improved.md`.

## 2026-10-19 · Phase 5: Temporal feasibility · DONE

- **Implemented:** `src/audit/temporal.py`.
- **Executed** in 9.5 s, from the timeline cache.
- **Outputs:** `temporal_feasibility.json`, `attack_segments.csv` (445 segments at 60 s and 300 s gaps).
- **No sequence dataset was generated.**
- **Report:** `reports/temporal_feasibility.md`.

## 2026-10-19 · Phase 6: Leakage audit and evaluation design · DONE (protocol PROPOSED)

- **Implemented:** `src/audit/leakage.py` (separability, hashes, splits, conflicts); `configs/evaluation_protocol.yaml`.
- **Executed:** separability (336 s, then 320 s after the header-row fix), hashes (64 s), splits.
- **Design correction.** The forward-chaining folds were first described as "containing seen families". In fact the recurring 2018 family is in the **validation** day of each fold, not in training. The split audit now also measures test overlap with train + val and gives a per-family table (`split_family_leakage.csv`). The protocol states the refit-on-train+val rule.
- **Exclusion added.** The 2,609 stray rows of `Friday-23-02-2018` (21–22 Feb) are now excluded by the split audit through `row_exclusions`, with the count logged. Before, they stretched that file's time span, which distorts the within-day cuts.
- **Report:** `reports/evaluation_protocol.md`.

## 2026-10-19 · Phase 7: Research questions and literature · DONE (scoping only)

- 13 logged web queries (`reports/literature_review.md`). Only the CNS2022 paper, its code and the release pages were read in full.
- Hypotheses H1–H7 with experiments E1–E7: `reports/research_questions.md`, `configs/experiment_matrix.yaml`.
- Novelty remains **HYPOTHESIS** until a systematic search is done (to do).

## 2026-10-19 · Close-out: re-runs, notebooks, tests, final checks

**Re-runs after the corrections** (all rc 0):

| Step | Time |
|---|---|
| duplicates | 334 s |
| separability | 320 s |
| matching | 184 s |
| splits, with exclusion and train+val | 369 s |
| splits, again with P1b added | 523 s |
| conflicts | 28 s |
| `report.py phase3` | 200 findings |
| `report.py phase6` | 87 leakage rows |
| `compare.py summary` | 40 rows |

**Added**

- A **P1b** within-day split cut at flow-count quantiles (diagnostic). Result: test attacks 76,800 (2017) and 15,184 (2018), but the embargo removes 716,549 attack flows in 2018, and the split leaks across days.
- `leakage.py conflicts` → `label_conflict_composition.csv`.
  - The first version aggregated lists over every feature hash and was **stopped by hand** after about 10 min, with no output written. It was rewritten to find conflicting groups with min/max first.
  - Result: the binary floor (minimum unavoidable error) is **65 rows** in 2018 improved, mostly FTP-Attempted versus 60 benign flows. The 2017 floor is 4,946 rows, mostly `Portscan` versus `Infiltration – Portscan`.
- **Notebook generator** (`make_notebooks.py`) now refuses to overwrite existing notebooks without `--overwrite`, and never overwrites the figure.
- **Report wording fixed:** `report.py phase6` gave every split the P0-specific action text, and timestamp parse failures now name the header rows behind them.

**Validated**

- `python -m pytest -q` → **36 passed**. This includes a new test of the flow-quantile split with excluded rows.
- `python -I src/audit/make_notebooks.py --execute` → **6/6 notebooks executed, 0 errors**. The independent re-checks inside them:
  - re-hash of `friday.csv` = manifest;
  - headers re-read = saved schema;
  - comma-only lines = 288,602;
  - transition matrix = 4 rows.

  The figure was written to `results/audit/figures/`. The kernel runs without `-I`, but its working directory and path contain only project code.
- `python -I src/audit/inventory.py scan --overwrite` → 52 inventory rows, now covering `data/raw_*`.
- `python -I src/audit/acquire.py verify --out data/manifests/acquisition_verification_final.csv` → **33/33 raw CSVs re-hashed and unchanged**. Both zips are unchanged (size and mtime equal the hashed record).

**Rules kept**

- No package was installed.
- No model was trained.
- Nothing was committed (the folder is not a Git repository).
- No raw file was modified.

**Status.** Phases 0–7 are complete. **Phase 8 is not started; it waits for the user's review.**

---

## 2026-10-19 · User request "Yes do 123" (after the close-out)

The user answered two clarifying questions:

- "do 1" means **self-review only**. No Phase 8.
- For OneDrive: **move the raw data out and leave junctions**.

"Yes" was read as accepting the offer to publish the audit report as a page.

### Item 3: raw data moved out of OneDrive

- **Before the move:** OneDrive was not running, and no raw file had cloud attributes.
- **Move:** `data/raw_improved` and `data/raw_original` (33 files, 45.3 GB) were moved to `C:\nids_data\`. On the same drive this is a rename. Directory junctions with the old names were left in their place.
- **Verification:** `acquire.py verify --out data/manifests/acquisition_verification_after_relocation.csv` re-hashed all 33 files and found them unchanged (56 s).
- **Not moved:** the two zips (10.8 GB) were already in the folder before this project started.

### Item 2: systematic literature search

- **Tool:** `src/lit/citation_search.py` (fetch, screen, search).
  - Forward citations of CNS2022 and Engelen 2021, from OpenAlex and Semantic Scholar: **421 unique works**.
  - 14 logged OpenAlex keyword queries.
  - A transparent keyword screen, then manual review. 21 decisions are recorded in `results/literature/manual_screening.csv`.
- **Key finding:** next-window network-state forecasting on CSE-CIC-IDS2018 is already published (SENTINEL, a 2026 preprint). So are day-chronological evaluation and an audit of the corrected CIC-IDS2017 (IDS2Eval).
  - The gap assessment was revised in `reports/literature_review.md` §5 and in `research_questions.md`.
  - Recommended reframing: a measurement study.
- **Not obtained automatically:**
  - Zenodo and Preprints.org returned HTTP 403. They were not retried by other means.
  - Two IEEE papers are paywalled.
  - The IDS2Eval paper itself was not found.

### Item 1: self-review (`reports/self_review.md`)

**A. Independent recomputation** (`src/audit/self_review.py`; pyarrow + pandas, no DuckDB, no caches; about 45 GB streamed):

- **17/17 checks agree** with the pipeline. They include 4,359,069 of 4,359,069 attack and Attempted flows inside their windows, 263,004 duplicates, the conflict floor of 4,946, and the 12-hour clocks.
- **New corrected figure:** without the stray rows, the 2018 next-window positive rate is **10.35%**, not 7.39%.

**B. Report-claim check** (`src/audit/check_claims.py`): 32 headline numbers are now found verbatim in the reports. The first run found 1 error.

**C. Errors found and fixed:**

1. The 2018 next-window rate included the stray span (7.39% → 10.35%).
2. The 2017 persistence share was given as 71–73%; it is **67–73%** across horizons. The "about 1,600" onset-like transitions were really 1,529–2,009.
3. Three outputs contained absolute paths with the user name. The code now writes `%TEMP%/…` and project-relative paths. `labelling_windows.py` was re-run; only the `notebook` column changed. In the two cache manifests, the prefix was replaced.
4. The persistence baseline was an oracle. **Detector persistence** is now the fair baseline, and oracle persistence is reported as an upper bound.
5. E1 used P1, which has 0 test attacks in 2018. E2's falsification rule did not match H4. A pre-registration item was added for the "small" threshold.

**Own slip during this session:**

- Patch scripts written through the shell turned `\n` and `\r` in `C:\nids_data\raw_…` into control characters in 4 files, which broke `datasets.yaml`.
- Python `write_text` had also switched 15 edited files to CRLF.
- Both were repaired: the paths fixed, every edited text file normalised to LF, all YAML re-parsed, and tests re-run.

**Validated:** `python -m pytest -q` → **39 passed**, including the new `tests/test_self_review.py`.

**Rules kept:** no packages installed, no model trained, nothing committed, and no raw file modified (33/33 re-hashed after the move).

## 2026-10-19 · Study papers downloaded (user request)

- **Folder:** `study/` holds the study-guide papers, one sub-folder per step, plus `README.md` (reading and printing guide) and `download_log.csv` (source URL, SHA-256, status).
- **Tool:** `src/lit/fetch_study_papers.py`. It uses open sources only, never overwrites a file, checks each file's format, and tries every URL once.
- **Obtained: 16 files.**
  - 14 PDFs and 1 RFC as text, downloaded.
  - The CNS2022 PDF, copied from the project.
  - Every PDF's first page was checked with pypdf, and all match their titles.
- **Not obtained, and listed in `study/README.md`:**
  - **Sites refused automated download** (HTTP 403 or a challenge page): OTexts (FPP3), ACM DL (Axelsson), MDPI (Ji 2023), BMJ (PRISMA), HAL (Lanvin). They were not retried; the user downloads them in a browser.
  - **Paywalled or books:** Kaufman 2012, D'hooge 2022, Husák 2019, the IEEE 2025 papers, and the three books.
  - **Fetches I corrected myself:**
    - The RFC PDF path no longer exists, so the plain-text RFC was used.
    - Python's certificate store could not verify KU Leuven Lirias, so `curl` with the Windows store was used; certificate checks stayed on.
    - Rosay 2022 had no file on HAL, so the SciTePress open copy was used.
- **Not used:** copies of paywalled papers uploaded by third parties (course sites, document-sharing sites).
