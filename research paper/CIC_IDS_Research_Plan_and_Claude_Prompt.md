# CIC-IDS Research Execution Plan and Claude Code Work Order

**Project:** Reproducible dataset audit and research workflow for
temporal Network Intrusion Detection (NIDS)\
**Datasets:** Improved CIC-IDS-2017 and fixed/improved CSE-CIC-IDS-2018
released with or following *Error Prevalence in NIDS Datasets: A Case
Study on CIC-IDS-2017 and CSE-CIC-IDS-2018* (IEEE CNS 2022)\
**Current state:** EDA has already been performed on the original CIC
data. Improved versions have now been downloaded.\
**Primary research direction:** Temporal network-state modeling and
early attack prediction.\
**Execution mode:** Claude Code working in the existing project
environment.\
**Priority:** Correctness, traceability, reproducibility, and clean
organization before model complexity.

------------------------------------------------------------------------

## 1. Mission

Audit the downloaded improved CIC-IDS datasets, verify exactly what
versions and files are present, compare them with the original datasets
and prior EDA where available, and create a reproducible foundation for
a research paper on temporal intrusion detection and early attack
prediction.

Do **not** jump directly into model training. The first deliverable is a
verified dataset inventory and audit report. Every conclusion must be
supported by a saved artifact, explicit calculation, source reference,
or reproducible command.

## 2. Non-negotiable rules

1.  **Never modify, rename, move, overwrite, or delete raw source
    data.** Treat `data/raw_original/` and `data/raw_improved/` as
    immutable inputs.
2.  Do not assume that "improved," "fixed," or "corrected" means a
    particular release. Verify the dataset's provenance from its README,
    download page, filenames, release notes, and accompanying code.
    Record uncertainty explicitly.
3.  Do not invent results, data characteristics, correction claims,
    citations, or model performance.
4.  Do not load all large CSV/Parquet files into memory by default. Use
    metadata inspection, chunked reads, column projection, and bounded
    samples where appropriate.
5.  Use the existing Python environment and installed packages first.
    **Do not install packages or upgrade Python/dependencies without
    asking the user first.** If a needed package is missing, document
    the blocker and offer the smallest possible option.
6.  Do not silently drop rows, features, labels, attack classes, or
    days. Every exclusion must be justified, counted, logged, and
    reproducible.
7.  Never use the label, future-derived information, capture identity,
    file name, or other unavailable-at-inference information as a model
    input. Separate metadata/targets from features.
8.  No random row-level split for the main temporal forecasting claim.
    Use chronological and/or scenario-held-out evaluation with leakage
    checks.
9.  Do not create synthetic data or fill unknown labels with guessed
    values. Missingness and ambiguity must be reported.
10. Keep notebooks, scripts, configs, logs, manifests, results, and
    reports in their designated folders. Avoid dumping files into the
    repository root.
11. Do not claim that a temporal sequence represents real two-second
    network states until timestamps, aggregation semantics, and window
    continuity have been verified.
12. Do not begin expensive processing or training without reporting
    expected input size, memory implications, and output size. For
    expensive steps, provide a dry-run or bounded pilot first.
13. Preserve reproducibility: fixed configuration, random seeds where
    relevant, environment/package record, command logs, data manifests,
    and checksums.
14. Do not commit data, secrets, credentials, or large generated
    artifacts to Git. Check `.gitignore` and repository status before
    any Git operation. Do not commit or push unless explicitly
    authorized.

## 3. Target repository structure

First inspect the existing repository. Reuse and adapt existing files
rather than duplicating them. If no structure exists, establish:

``` text
nids-research/
├── README.md
├── .gitignore
├── data/
│   ├── raw_original/
│   │   ├── CIC-IDS-2017/
│   │   └── CSE-CIC-IDS-2018/
│   ├── raw_improved/
│   │   ├── CIC-IDS-2017/
│   │   └── CSE-CIC-IDS-2018/
│   ├── manifests/
│   └── processed/                 # empty until approved by audit
├── notebooks/
│   ├── 01_dataset_inventory.ipynb
│   ├── 02_provenance_and_schema.ipynb
│   ├── 03_integrity_audit.ipynb
│   ├── 04_original_vs_improved.ipynb
│   ├── 05_temporal_structure.ipynb
│   └── 06_leakage_and_split_design.ipynb
├── src/
│   ├── audit/
│   ├── preprocessing/
│   ├── evaluation/
│   └── models/
├── configs/
├── results/
│   ├── audit/
│   ├── baselines/
│   └── experiments/
├── reports/
│   ├── literature_review.md
│   ├── dataset_provenance.md
│   ├── dataset_audit_report.md
│   └── research_questions.md
├── logs/
└── environment/
```

If the user's existing directory differs, preserve it and document the
mapping in `reports/project_layout.md`. Do not create a second competing
project root.

## 4. Phased work plan and acceptance criteria

### Phase 0 --- Repository and environment reconnaissance

**Tasks** - Print the current working directory, repository root,
directory tree (bounded depth), Git status if applicable, Python
version, and installed versions of relevant libraries. - Identify
existing notebooks, scripts, original dataset locations, prior EDA
outputs, and any existing preprocessing code. - Identify actual
locations of both improved datasets. Do not move them just to match the
proposed structure. - Check disk space before any large operation. -
Record the command used to run each script and its output/log
location. - Inspect `.gitignore`; ensure raw datasets, credentials, and
large generated files are excluded appropriately without deleting or
rewriting user rules unnecessarily.

**Deliverables** - `reports/project_layout.md` -
`environment/python_environment.txt` - `logs/phase0_reconnaissance.txt`

**Acceptance criteria** - Existing work is discovered and reused. - Raw
file locations are known. - No raw data was changed. - No dependency was
installed or upgraded.

### Phase 1 --- Dataset inventory and provenance

**Tasks** - Recursively inventory all files in both improved datasets
and, where available, the original datasets. - Record dataset family,
version/release as verified, filename, relative path, extension/format,
file size in bytes, modification time (as filesystem metadata only), and
whether the file is data, documentation, archive, script, or other. -
Calculate SHA-256 checksums for downloaded data files when practical.
For large files, stream the checksum in chunks and report progress. Do
not checksum the same large file repeatedly. - Inspect archives without
extracting over existing files. List archive members and sizes first;
detect nested archives. - Locate READMEs, release notes, correction
scripts, feature documentation, label mapping, and citations from the
dataset authors. - Record exact source URLs and access date if known
from local documentation or user-provided source. Do not claim online
verification if no web access was performed. - Distinguish verified
facts from assumptions and unresolved questions. - Check for incomplete
downloads and suspiciously small/empty files; do not label a file
corrupt without evidence.

**Deliverables** - `data/manifests/dataset_inventory.csv` -
`data/manifests/checksums_sha256.csv` -
`data/manifests/archive_contents.csv` if archives exist -
`reports/dataset_provenance.md` - `logs/phase1_inventory.log`

**Acceptance criteria** - Both improved dataset families are
inventoried. - Original datasets are inventoried if accessible. -
Version and correction lineage are documented with confidence levels. -
No raw file was modified or extracted over another file.

### Phase 2 --- Schema and label audit

**Tasks** - Identify formats and choose efficient readers already
installed. - For each data file, inspect schema, column names, types,
row count where safely obtainable, and basic metadata. - For CSVs, use
bounded/chunked reads for large files; do not rely on a tiny sample to
claim a complete label distribution. - For Parquet, inspect
metadata/schema first; use row-group statistics where available. If a
known PyArrow error occurs, record the exact error and stop that read
path rather than repeatedly retrying or altering the file. - Identify
label columns and preserve original label strings exactly before
creating any normalized mapping. - Calculate label counts and
proportions, including missing/unknown labels, using a full scan when
feasible. - Record per-file feature schema, target schema, timestamp
fields, identifiers, metadata columns, and fields that may encode
file/day/scenario identity. - Compare schemas between original and
improved versions. Explicitly classify columns as unchanged, renamed,
added, removed, type-changed, or value-changed where a meaningful
comparison is possible. - Do not assume different files can be
row-aligned. Match rows only using a documented stable key or defensible
multi-column key; report match coverage and ambiguity. - Inspect feature
names for spaces, duplicate names, case variations, and suspiciously
duplicated columns without silently renaming the source data.

**Deliverables** - `results/audit/schema_by_file.json` -
`results/audit/label_distribution_by_file.csv` -
`results/audit/schema_diff_original_vs_improved.csv` where originals are
available - `reports/schema_and_labels.md` - Notebook
`02_provenance_and_schema.ipynb`

**Acceptance criteria** - Label counts are based on a documented method
and scope. - No label remapping happens silently. - Schema differences
are reported rather than automatically "fixed."

### Phase 3 --- Integrity and quality audit

**Tasks** Audit each dataset and file, with both per-file and aggregate
summaries where valid: - Missing/null/blank values. - Positive and
negative infinity, NaN, parse failures, and nonnumeric values in numeric
features. - Exact duplicate rows and duplicate candidate flow records. -
Duplicate/constant columns and highly suspicious feature duplication. -
Numeric distributions, ranges, quantiles, and outlier counts; flag for
review rather than automatically deleting outliers. - Invalid or
physically implausible values (for example, negative durations or
impossible packet/byte counts) using feature semantics and documented
units. Distinguish genuine invalidity from unfamiliar encoding. - Label
inconsistencies and ambiguous/missing labels. - Timestamp parse
failures, timezone assumptions, time ordering, duplicated timestamps,
and gaps. - Per-file differences and unusual class imbalance. - Feature
columns that appear to reveal labels or capture artifacts. - If original
and improved data both exist, compare these metrics side-by-side.

For each finding, record: - Dataset/file/column scope. - Detection rule
and threshold. - Count and denominator. - Severity
(critical/high/medium/low) and rationale. - Evidence and proposed
action. - Whether the action is automatic, requires review, or is
deferred.

**Do not remove or repair anything during the audit phase.** Produce
findings and a separate proposed cleaning plan.

**Deliverables** - `results/audit/integrity_summary.json` -
`results/audit/missingness_by_file.csv` -
`results/audit/duplicates_by_file.csv` -
`results/audit/numeric_feature_summary.csv` -
`results/audit/timestamp_quality.csv` - `results/audit/findings.csv` -
`reports/dataset_audit_report.md` - Notebook `03_integrity_audit.ipynb`

**Acceptance criteria** - Every reported count has a denominator and
clear scope. - Audit is read-only. - No row/feature/label was dropped or
repaired.

### Phase 4 --- Original-versus-improved comparison

**Tasks** - Compare provenance, schema, row/flow counts, labels, feature
distributions, missingness, duplicates, timestamp coverage, and known
correction notes. - Establish whether a direct row-level comparison is
valid. If not, use file-level or distributional comparison and
explicitly state the limitation. - Where a reliable matching key exists,
report matched/unmatched records and changed labels/features; do not
infer row correspondence from row order. - Quantify which differences
could affect downstream temporal modeling. - Separate changes made by
dataset authors from differences caused by file format, extraction
settings, preprocessing, or aggregation. - Map every observed difference
to supporting evidence or mark it unresolved.

**Deliverables** - `results/audit/original_vs_improved_summary.csv` -
`results/audit/feature_distribution_comparison.csv` where feasible -
`results/audit/label_transition_matrix.csv` where row matching is
defensible - `reports/original_vs_improved.md` - Notebook
`04_original_vs_improved.ipynb`

**Acceptance criteria** - Comparisons are fair and reproducible. - No
unsupported claim that all errors have been eliminated. - Differences
without a defensible matching key are not described as per-row
corrections.

### Phase 5 --- Temporal feasibility and forecasting-target design

**Tasks** - Determine what each row represents: flow, packet, aggregate
window, or another unit. Verify from documentation and observed
fields. - Establish timestamp semantics, timestamp granularity,
timezone, ordering, capture/day/scenario boundaries, and whether
multiple files overlap in time. - Check whether the improved CSV/Parquet
data has enough information to construct consecutive two-second
network-state windows. Do not infer continuity merely from sorted
timestamps. - Define the temporal unit and aggregation rules before
building sequences. - Verify which attack labels have onset/end timing
and which labels may only identify flow-level involvement. - Define a
forecastable attack onset only when supported by labels and timestamps.
If labels cannot support a reliable onset, state that limitation and
reframe the task (for example, next-window attack-state prediction
rather than onset forecasting). - Prevent windows/sequences from
crossing capture-day, file, or scenario boundaries unless continuity is
verified. - Define target horizons, such as one to five two-second
steps, only if the timestamp and label granularity support them. -
Separate current-state classification from future attack prediction.
They are not the same target. - Identify censoring, missing periods, and
ambiguous attack transitions.

**Deliverables** - `reports/temporal_feasibility.md` -
`results/audit/temporal_feasibility.json` - Notebook
`05_temporal_structure.ipynb` - A proposed target definition with
examples and known limitations.

**Acceptance criteria** - Forecasting targets have a defensible temporal
interpretation. - No model or sequence dataset is generated yet unless
explicitly approved after audit.

### Phase 6 --- Leakage audit and evaluation design

**Tasks** - Identify direct target leakage, post-event features,
labels/label derivatives, IDs, file names, day/scenario identifiers, and
other unavailable-at-inference fields. - Check exact and near-duplicate
records across candidate partitions. - Document features whose values
may encode the collection process or attack-generation setup. - Specify
a chronological train/validation/test split within the primary dataset,
respecting day/scenario boundaries where possible. - Specify a separate
unseen-day or unseen-scenario test if the dataset supports it. - Plan
external transfer to the other CIC dataset; first document feature/label
compatibility. Do not assume labels are interchangeable. - Consider
CTU-13 only as a later external benchmark after the CIC audit, not as a
prerequisite for this phase. - Define a preprocessing fit policy:
scalers, imputers, feature selection, and thresholds must be fit on
training data only. - Specify baselines and metrics before model
tuning. - Create split manifests with file/row/time ranges and hashes so
experiments can reproduce the same partitions. - Use random row splits
only as a diagnostic comparison, never as the primary evidence for a
temporal forecasting claim.

**Deliverables** - `results/audit/leakage_findings.csv` -
`reports/evaluation_protocol.md` - `configs/data_audit.yaml` -
`configs/evaluation_protocol.yaml` - Notebook
`06_leakage_and_split_design.ipynb`

**Acceptance criteria** - Proposed split avoids temporal and duplicate
leakage. - Train-only fitting is documented. - No model training is
started before the user reviews the audit and protocol.

### Phase 7 --- Research gap and hypothesis formulation

Only after Phases 1--6: - Review the 2022 paper's exact claims,
corrections, released artifacts, and limitations. - Separate what that
paper establishes from what later studies establish. - Formulate a small
number of falsifiable hypotheses. Candidate directions to assess, not
assume as novel: 1. Corrected dataset versions materially change
temporal forecasting performance compared with original versions. 2.
Random splits overestimate performance relative to chronological and
scenario-held-out evaluation. 3. Dataset-specific artifacts reduce
cross-dataset transfer. 4. Multi-horizon attack prediction is harder
than same-window attack classification. - Search literature to verify
novelty before claiming a research gap. Record search queries, dates,
and citations. - Define the primary contribution, baselines, ablations,
metrics, and statistical uncertainty plan. - Avoid claiming novelty
merely because a Transformer, LSTM, or "world model" is applied to CIC
data.

**Deliverables** - `reports/research_questions.md` -
`reports/literature_review.md` - `configs/experiment_matrix.yaml`

### Phase 8 --- Baselines and modeling (not authorized until audit review)

After the user approves the audit and evaluation design: - Build
reproducible preprocessing that emits new files only under
`data/processed/`. - Add unit tests for timestamp parsing, feature
selection, label mapping, sequence boundaries, and split leakage. -
Establish simple baselines first: majority/stratified baseline,
persistence, logistic regression or tree-based model, and an appropriate
temporal baseline. - Compare against LSTM/TCN/Transformer only after
baselines and target definitions are sound. - For early warning, report
detection lead time, precision/recall at fixed operating points, false
alerts per unit time, PR-AUC where appropriate, and performance by
attack/scenario. - Report confidence intervals or repeated-seed
variability where computationally practical. - Run ablations for
corrected versus original data, split protocol, feature groups, and
prediction horizon. - Keep model outputs, configs, checkpoints, and logs
in `results/experiments/`; never overwrite earlier runs. - Do not make
performance claims without reproducible logs and saved evaluation
outputs.

## 5. Research design guardrails

### Distinguish the tasks

-   **Current-window detection:** infer whether the current window is
    malicious.
-   **Next-window prediction:** predict the attack state in a future
    window.
-   **Attack-onset forecasting:** predict an upcoming transition from
    non-attack to attack before it occurs.
-   **Attack-stage/trajectory prediction:** predict a future stage or
    sequence of stages.

Choose only targets supported by the dataset's temporal and labeling
semantics. A strong current-window classifier is not proof of early
warning.

### Distinguish evidence levels

Use explicit status labels in reports: - **Verified:** directly
supported by the downloaded data or a reproducible test. -
**Documented:** stated by the dataset authors/paper but not
independently revalidated. - **Hypothesis:** plausible and awaiting
testing. - **Unresolved:** evidence is insufficient or conflicting.

### Evaluation principles

-   Do not use accuracy alone for imbalanced attack classes.
-   Report class-wise metrics and the exact averaging scheme.
-   PR-AUC and operational false-positive rates may be more informative
    than ROC-AUC alone for rare attacks.
-   Thresholds must be selected on validation data, not test data.
-   Report both aggregate and per-day/per-scenario performance.
-   External transfer requires compatible labels/features and a
    documented mapping.
-   A test split is not independent if overlapping windows or duplicates
    leak across partitions.

## 6. Claude Code execution protocol

Claude should work in small, auditable phases and return a concise
checkpoint after each phase.

For every phase: 1. State the planned actions and expected outputs. 2.
Inspect the repository before creating files. 3. Execute only the
current phase. 4. Run relevant tests or sanity checks. 5. Report files
created/modified, commands run, elapsed time if available, warnings, and
any failure. 6. Update a persistent `reports/WORK_LOG.md` with
date/time, phase, status, findings, outputs, and next action. 7. Stop at
the phase boundary and wait for user approval before expensive
processing or moving into the next phase where specified.

Do not claim work is complete if a script was merely written but not
run. Clearly distinguish **implemented**, **executed**, and
**validated**.

------------------------------------------------------------------------

# 7. Copy/paste prompt for Claude Code

Paste the following into Claude Code from the root of the existing NIDS
research project. Edit the project path only if necessary.

``` text
You are the research engineer responsible for the reproducible dataset-audit stage of my Network Intrusion Detection research project.

RESEARCH GOAL
I am investigating temporal network-state modeling and early attack prediction using the improved CIC-IDS-2017 and fixed/improved CSE-CIC-IDS-2018 datasets associated with the paper:
“Error Prevalence in NIDS Datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018” (IEEE CNS 2022).

I previously performed EDA on the ORIGINAL CIC dataset(s). I have now downloaded BOTH improved dataset families. Your first job is to establish provenance and audit the improved versions, then compare them with the originals and my prior EDA wherever the relevant files are available.

OPERATING CONSTRAINTS — MUST FOLLOW
- Start by inspecting the current working directory and repository. Do not assume a path or create a second project root.
- Preserve all raw data. Never edit, rename, move, overwrite, delete, or extract over existing raw files.
- Do not install, upgrade, or uninstall packages without asking me first. Use the current environment.
- Do not train a model during the initial audit.
- Do not run expensive full-data jobs until you estimate resource needs and run a bounded/dry-run check.
- Do not invent results, source URLs, citations, dataset versions, row counts, or correction claims.
- Do not infer row-level corrections from row order. Match rows only using a documented stable key or a defensible multi-column key, and report match coverage.
- Do not silently drop rows, columns, classes, labels, or days.
- Do not treat file names, labels, day/scenario identifiers, or post-event fields as model features.
- Do not use random row-level splitting as the main evaluation protocol for temporal forecasting.
- Use efficient metadata inspection and chunked reads. Avoid loading all large files into RAM.
- Keep outputs organized. Do not dump files into the repository root.
- Do not commit or push anything. Do not include raw datasets or secrets in Git.
- Clearly label each result as VERIFIED, DOCUMENTED, HYPOTHESIS, or UNRESOLVED.
- Clearly distinguish a script that was written from a script that was executed and validated.

FIRST ACTION: RECONNAISSANCE ONLY
1. Print the working directory and identify the repository root.
2. Inspect the current project tree to a bounded depth.
3. Locate the original datasets, both improved datasets, previous EDA notebooks/scripts, README files, existing processed artifacts, and relevant logs.
4. Record Python version and installed versions of relevant already-installed packages (at least pandas, numpy, pyarrow if available, scikit-learn, matplotlib; do not install missing packages).
5. Check disk space if possible and inspect .gitignore and Git status if this is a Git repository.
6. Do not move files. If paths differ from the suggested layout, document the mapping.
7. Save the reconnaissance log and a project-layout report in the existing project.

TARGET STRUCTURE
Reuse existing structure where possible. Otherwise use:
data/raw_original/CIC-IDS-2017/
data/raw_original/CSE-CIC-IDS-2018/
data/raw_improved/CIC-IDS-2017/
data/raw_improved/CSE-CIC-IDS-2018/
data/manifests/
data/processed/
notebooks/
src/audit/
src/preprocessing/
src/evaluation/
src/models/
configs/
results/audit/
results/baselines/
results/experiments/
reports/
logs/
environment/

PHASE 1 — INVENTORY AND PROVENANCE
- Recursively inventory both improved datasets and original datasets if present.
- Record dataset family, verified release/version, relative path, filename, extension, file size in bytes, file type, and relevant archive metadata.
- Locate and read local README/release notes/correction scripts/feature and label documentation.
- For archives, list members and sizes before extraction. Never extract over existing files.
- Compute streaming SHA-256 checksums for data files where practical; do not repeatedly hash huge files.
- Save:
  data/manifests/dataset_inventory.csv
  data/manifests/checksums_sha256.csv
  data/manifests/archive_contents.csv (if applicable)
  reports/dataset_provenance.md
  reports/project_layout.md
  environment/python_environment.txt
  logs/phase1_inventory.log
- Distinguish verified release information from assumptions. If online verification is needed but you do not have web access, record that as unresolved rather than pretending it was checked.

PHASE 2 — SCHEMA AND LABEL AUDIT
- Inspect file formats and schemas without loading full files unnecessarily.
- For CSV use bounded/chunked reading. For Parquet inspect metadata/schema first and use row-group statistics when available.
- If a read fails (including any PyArrow/parquet corruption or metadata error), capture the exact exception and stop retrying the same method; do not alter the raw file.
- Record columns, types, label fields, timestamp fields, IDs, metadata, and candidate leakage fields.
- Compute full-file label counts only with a documented full scan; label sample-based estimates as samples.
- Compare original and improved schemas, recording added/removed/renamed/type-changed columns.
- Never assume row order establishes correspondence.
- Save:
  results/audit/schema_by_file.json
  results/audit/label_distribution_by_file.csv
  results/audit/schema_diff_original_vs_improved.csv (if original data exists)
  reports/schema_and_labels.md
  notebooks/02_provenance_and_schema.ipynb
- Make the notebook executable in the current environment and document whether it was actually executed.

PHASE 3 — INTEGRITY AUDIT (READ-ONLY)
Check, with counts and denominators:
- Missing/null/blank values and parse failures.
- NaN and positive/negative infinity.
- Exact duplicate rows and candidate duplicate flows.
- Duplicate/constant columns.
- Numeric ranges, quantiles, and suspicious feature values.
- Negative durations and physically implausible counters where semantics justify a check.
- Label inconsistencies, unknown labels, and class imbalance.
- Timestamp parsing, timezone assumptions, ordering, duplicates, and gaps.
- Per-file and cross-file anomalies.
- Potential label leakage and capture/scenario artifacts.
Do not delete or repair data. Produce findings and recommendations only.
Every finding must contain scope, rule, count, denominator, severity, rationale, evidence, and recommended next action.
Save:
results/audit/integrity_summary.json
results/audit/missingness_by_file.csv
results/audit/duplicates_by_file.csv
results/audit/numeric_feature_summary.csv
results/audit/timestamp_quality.csv
results/audit/findings.csv
reports/dataset_audit_report.md
notebooks/03_integrity_audit.ipynb

PHASE 4 — ORIGINAL VS IMPROVED
- Compare file counts, rows/flows where measurable, labels, feature schema, missingness, duplicates, distributions, and timestamp coverage.
- Use row-level comparison only if a defensible key exists; report matched/unmatched counts and ambiguity.
- Otherwise compare file-level or distribution-level properties and state the limitation.
- Map observations to the authors’ documented corrections where evidence exists.
- Do not claim the improved data is error-free.
Save:
results/audit/original_vs_improved_summary.csv
results/audit/feature_distribution_comparison.csv (where feasible)
results/audit/label_transition_matrix.csv (only if row matching is defensible)
reports/original_vs_improved.md
notebooks/04_original_vs_improved.ipynb

PHASE 5 — TEMPORAL FEASIBILITY (NO SEQUENCE GENERATION YET)
- Determine what each row represents and the semantics of its timestamps.
- Verify whether the data supports reliable consecutive two-second network-state aggregation.
- Determine whether files/days/scenarios overlap and where capture boundaries occur.
- Check whether labels and timestamps support attack-onset forecasting. If not, recommend a narrower valid target such as next-window attack-state prediction.
- Define candidate targets separately: current-window detection, next-window prediction, attack-onset forecasting, and future attack-stage prediction.
- Prevent sequences from crossing file/day/scenario boundaries unless continuity is verified.
- Do not assume a flow-level label provides precise attack onset time.
Save:
reports/temporal_feasibility.md
results/audit/temporal_feasibility.json
notebooks/05_temporal_structure.ipynb

PHASE 6 — LEAKAGE AUDIT AND EVALUATION PLAN
- Identify label-derived fields, IDs, file/day/scenario identity, post-event features, duplicate/near-duplicate records, and other unavailable-at-inference features.
- Propose chronological train/validation/test partitions and scenario/day-held-out evaluation where supported.
- Plan CIC-2018-to-CIC-2017 transfer only after feature/label compatibility is documented.
- Define preprocessing fit on training data only.
- Create reproducible split-manifest design, but do not materialize large splits or train models yet.
- Define metrics appropriate for imbalance and early warning: class-wise precision/recall/F1, macro-F1, PR-AUC where appropriate, false-positive rate at a validation-selected threshold, false alerts per unit time, and detection lead time when onset labels support it.
- State that random row split is diagnostic only, not primary evidence for temporal forecasting.
Save:
results/audit/leakage_findings.csv
reports/evaluation_protocol.md
configs/data_audit.yaml
configs/evaluation_protocol.yaml
notebooks/06_leakage_and_split_design.ipynb

PHASE 7 — RESEARCH QUESTIONS
Only after the audit, summarize what the 2022 paper establishes versus what remains untested. Formulate falsifiable hypotheses about correction effects, split sensitivity, cross-dataset transfer, and multi-horizon forecasting. Do not claim novelty without a literature check. Record queries, dates, and sources.
Save:
reports/research_questions.md
reports/literature_review.md
configs/experiment_matrix.yaml

ENGINEERING REQUIREMENTS
- Create reusable scripts in src/audit/; notebooks should call these functions instead of duplicating complex logic.
- Add clear docstrings, type hints where practical, and explicit input/output paths.
- Make scripts runnable from the project root with clear command-line arguments or a documented config.
- Use deterministic ordering and fixed random seeds for any sampling.
- Record tool versions and execution commands.
- Log failures and warnings; do not suppress them.
- Add tests for core parsing, label mapping, timestamp handling, and any matching logic if feasible with existing packages. Do not create tests that require copying the entire dataset.
- Update README.md with the workflow, folder layout, commands, expected outputs, and safety rules.
- Maintain reports/WORK_LOG.md after every phase with timestamp, status, actions, commands, outputs, findings, failures, and next step.
- Use only relative project paths in reports when possible; do not expose private machine details unnecessarily.
- Ensure all generated artifacts are written to designated folders.
- Never silently overwrite an existing report or output. Use a versioned output or ask first if replacement is needed.

CHECKPOINT / STOP RULE
Work in small phases. Complete Phase 0 reconnaissance and Phase 1 inventory first. Then show me:
1. the discovered repository/data paths,
2. the file inventory summary for both improved datasets,
3. provenance/version confidence and unresolved questions,
4. files created,
5. commands actually run and which completed successfully,
6. any resource or dependency blockers,
7. the proposed next phase.

STOP after Phase 1 and wait for my approval before running full schema/integrity scans or other potentially expensive operations. Do not train a model. Do not say the audit is complete if only inventory was done.
```

## 8. Final completion checklist

Before calling the audit stage complete, confirm: - \[ \] Both improved
dataset versions and their provenance are documented. - \[ \] Original
data and prior EDA are preserved and located. - \[ \] Inventory and
checksums are saved. - \[ \] Schema and label distributions have
documented scope. - \[ \] Integrity findings include counts,
denominators, and severity. - \[ \] Original-versus-improved comparisons
avoid invalid row matching. - \[ \] Temporal target feasibility is
established from actual data. - \[ \] Leakage and split design are
documented. - \[ \] Research questions are falsifiable and novelty is
not assumed. - \[ \] Commands, package versions, outputs, and failures
are recorded. - \[ \] No raw data was changed and no unapproved
dependencies were installed. - \[ \] No model training was started
before audit review.

**Immediate next action:** Run Claude Code with the prompt above. It is
deliberately instructed to stop after reconnaissance and inventory so
you can inspect the discovered paths and data versions before
authorizing expensive scans.
