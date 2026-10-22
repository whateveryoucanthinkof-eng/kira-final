# Self-review of the audit (before Phase 8)

Done 2026-10-19 at the user's request ("self-review only"). Nothing was modelled.

**This is not a substitute for your review.** It is a second pass by the same assistant that did the audit. Its value comes from three things:

- the recomputation uses independent code and data paths;
- every report number is checked mechanically against the result tables;
- the evaluation design is questioned explicitly.

## 1. Method

| Part | What | Code | Output |
|---|---|---|---|
| A | **Independent recomputation** of headline numbers straight from the raw CSVs. It uses pyarrow, pandas and numpy, and shares no SQL, DuckDB reader or cache with the audit pipeline. About 45 GB was streamed once. | `src/audit/self_review.py` | `results/audit/self_review_checks.csv` |
| B | **Report-claim check:** 32 headline numbers recomputed from the result tables, formatted as the reports write them, and searched for verbatim in the reports | `src/audit/check_claims.py` | `results/audit/report_claims_check.csv` |
| C | **Critical reading** of methods, protocol and hypotheses, plus a systematic literature search | — | this report; `reports/literature_review.md` §5 |

## 2. Part A: independent recomputation (17 checks; 17 agree)

| Check | Claim | Result |
|---|---|---|
| R01, R07 | Row counts of all 15 improved files | equal, every file |
| R02 | 2017 improved: 263,004 feature-identical copies (83 columns, compared by value) | equal |
| R03 | 2017 improved: 14,140 rows in label-conflict groups; minimum unavoidable error 4,946 | equal |
| R04 | Improved int16 header-length overflow: negatives 309 / 472 (2017) and 10,039 / 17,509 (2018); every value within [−32,768, 32,767] | equal |
| R05 | Flows lasting more than 2 s: 23.9–30.7% (2017) and 22.3–38.1% (2018) of each file | equal |
| R06 | **All 517,410 (2017) + 3,841,659 (2018) = 4,359,069 attack and Attempted flows lie inside a documented labelling window**; 0 outside | equal |
| R08 | 2,609 stray flows dated before 23 Feb in `Friday-23-02-2018` | equal |
| R09a, b, c | Next-window target (windows, positives, persistent) for every improved file, and the published 2018 totals | equal |
| R09d | **New:** 2018 totals with the stray rows excluded | 214,422 windows, 22,183 positives, **10.35%** (the report said 7.39%; see §4) |
| R10 | Both original releases: 3,119,345 and 16,233,002 rows read; every parsed hour lies in 1–12 (2017: 1–5 and 8–12; 2018: 1–12) | equal; 12-hour clock confirmed |

**What this establishes.** The audit's central numbers do not depend on DuckDB, on the read-time caches (cp1252 transcoding, line-ending normalisation), or on the SQL queries. They come out the same from a separate reader.

## 3. Part B: do the reports quote the data? (32 claims)

- **First run:** 31 of 32 claims were found verbatim. The miss was the 2017 persistence share.
- **After fixing it:** 32 of 32 are found.

The claims cover row counts, duplicate shares, conflict floors, the label-window total, split leakage, episode counts, the persistence range, the long-flow share, the finding count, the capped files, the stray rows, `Dst Port` overlap, the P1b counts, the row-match coverage, and the literature counts.

## 4. Errors found by this self-review, and fixed

| # | Error | Fix | Status |
|---|---|---|---|
| 1 | **The 2018 next-window positive rate was given as 7.39%.** The window grid of `Friday-23-02` spanned the 21–22 Feb stray rows and added about 86,000 empty windows. | Recomputed without the stray rows: **10.35%** (214,422 windows). The persistence share is unchanged (92.7% at *h* = 1). | `reports/temporal_feasibility.md` §5 corrected |
| 2 | **The 2017 persistence share was given as 71–73%.** Only *h* = 1 and *h* = 5 had been read; *h* = 2–4 go down to 66.9%. **The "about 1,600" onset-like transitions** were really 1,529–2,009 per horizon. | Now **67–73%** and 1,529–2,009 | 4 reports corrected; now checked mechanically (Part B) |
| 3 | **Three outputs contained absolute paths with the Windows user name.** These were the labelling-rule table (`notebook` column) and two cache manifests (`cache_path`). | Code now writes project-relative or `%TEMP%/…` paths. `labelling_windows.py` was re-run, and the diff confirms only that column changed. The two manifests had the temp prefix replaced. | Fixed; no user-specific path remains in `results/`, `data/manifests/`, `reports/`, `configs/` or `notebooks/` |
| 4 | **The persistence baseline was an oracle.** It copied the *true* label of window *t*, which is not known in real time, so comparing against it alone is biased. | The protocol now requires **detector persistence** (carry forward the *h* = 0 detector's output) as the fair baseline, with **oracle persistence** reported as an upper bound. | `configs/evaluation_protocol.yaml`, `reports/evaluation_protocol.md` §9 |
| 5 | **E1 still used P1**, whose 2018 test partition has 0 attack flows. E2's falsification rule did not match H4, and "small" skill had no threshold. | E1 uses P1b, P2 and P3. E2 now has the same wording as H4, and has a `preregister_before_phase8` item for the threshold (PROPOSAL: a PR-AUC gain over detector persistence below 0.05) and for the onset definition. | `configs/experiment_matrix.yaml` |
| 6 | **The novelty claims were too broad.** The systematic search found prior work on next-window network-state forecasting on CSE-CIC-IDS2018 (SENTINEL, 2026 preprint), on day-chronological evaluation, and an audit of the corrected CIC-IDS2017 (IDS2Eval). | The gap assessment was revised, with a recommended reframing as a measurement study | `reports/literature_review.md` §5, `reports/research_questions.md` |

Errors found earlier in the session (duplicate counts including non-data rows; the 2018 originals' clock; the P1 artefact; the meaning of the P3 validation day) are listed in `reports/dataset_audit_report.md` §10 and `reports/WORK_LOG.md`.

## 5. Weaknesses that remain (not fixable inside the audit)

| Weakness | Consequence | Status |
|---|---|---|
| **The label audit checks one direction only.** Every attack label lies inside a documented window, but nobody checked whether every flow that matches a rule **was** labelled. Missed labels are not audited, because the authors' labelling code was deliberately not executed. | Hidden false negatives in "benign" are possible | UNRESOLVED; would need re-running the labelling logic |
| **UTC for the improved timestamps** rests on the authors' statement plus internal consistency with their own windows, which is partly circular. Independent support: the original clocks align at UTC−3 (July) and UTC−4 (February), which matches Atlantic time. | Small risk of a whole-hour shift; it would not affect windowing inside a day | DOCUMENTED + indirect VERIFIED |
| **Rows with Infinity/NaN were dropped before export**, according to the authors' code. How many is unknown. | Possible selection of zero-duration flows | UNRESOLVED |
| **Identity of the 2017 originals** | They cannot be cited as "the official release" | UNRESOLVED (no official checksum) |
| **Single-feature separability (OVL) uses coarse log2 bins and one feature at a time** | Flags are conservative; shortcuts that combine features are not measured | by design; E5 ablations cover part of it |
| **64-bit row hashes** for duplicates | Expected collisions among about 45M distinct 2018 vectors are about 45,000,000² / 2⁶⁵ ≈ 5×10⁻⁵, which is negligible. 2017 was confirmed with a second, independent hash (R02, R03). | acceptable |
| **The P3 folds are lopsided.** Test 23 Feb has 158 attack flows in 3 episodes. Test 21 Feb is 99.8% HOIC (1,082,293 of 1,084,023 attack flows). | Very wide CIs; aggregate scores are dominated by one family | Report per family and per episode (already required) |
| **Target definition by flow *start*** | Slow attacks with long flows start few flows, so the target flickers inside episodes. That is why onset-like transitions far outnumber true onsets. | Design choice to confirm (question 3 below) |
| **"Ended flows only" features delay long flows by up to 120 s** | Honest, but slow attacks may look harder to detect | Report per family; E7 measures the alternative |
| **Single screener** for the literature; 6 key works read at abstract level only (Zenodo/Preprints.org 403, IEEE paywall, IDS2Eval paper not found) | The novelty assessment is provisional | `reports/literature_review.md` §5.4 |
| **The notebook kernel runs without `-I`** | Its working directory and path contain only project code | acceptable |

## 6. Decisions for you before Phase 8

1. **Protocol.** Accept the recommended P3 forward-chaining folds (refit on train + val; recurring and unseen families scored separately), plus leave-one-day-out and cross-dataset transfer? (`configs/evaluation_protocol.yaml` `recommended`)
2. **Pre-registration.** The threshold for "small" skill over detector persistence (PROPOSAL: PR-AUC gain below 0.05), and the onset definition (300 s gap, ≥ *h* benign windows before it).
3. **Window target.** Keep "an attack flow *starts* in window *t* + *h*", or use "an attack flow is *active* in *t* + *h*"? The second is smoother for slow attacks, but uses flow end times that are unknown at prediction time, so it would need care.
4. **Attempted policy.** Should Attempted count as benign for the binary target (current primary), with ablations?
5. **Framing.** Given SENTINEL and the forecasting papers, should the paper be a measurement study, as recommended in `reports/literature_review.md` §5.3?
6. **Full texts.** Please download the 6 works that could not be fetched automatically, so related work and novelty can be finalised. The list is in `reports/literature_review.md` §5.4.
