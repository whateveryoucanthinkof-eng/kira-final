# Phase 6: Leakage audit and evaluation protocol

**Status: PROPOSED.** No model has been trained. The machine-readable version is `configs/evaluation_protocol.yaml`, and this report gives the evidence for each rule.

- **Code:** `src/audit/leakage.py` (separability, hashes, splits, conflicts) and `src/audit/report.py phase6`.
- **Outputs (`results/audit/`):**
  - `leakage_findings.csv`
  - `feature_separability.csv`
  - `split_design_coverage.csv`
  - `split_duplicate_leakage.csv`
  - `split_family_leakage.csv`
  - `label_conflict_composition.csv`

Unless stated otherwise, everything below concerns the **improved** releases, which are the only ones usable for temporal work (`reports/temporal_feasibility.md` §8).

**Two definitions used throughout.**

- **"Seen" feature vector:** an evaluation row whose exact feature vector (all feature and context columns, compared by value) also occurs in the training partition.
- **OVL:** the overlap of two class-conditional histograms. 0 means a single feature separates the classes; 1 means it carries no information.

## 1. Columns that are never model inputs (`leakage_findings.csv`, LEAK-001…009)

| Column | Why it is excluded | Evidence |
|---|---|---|
| `id` | The export row number. It encodes file order, which in 2018 is the per-host CSV concatenation order. It also separates classes by itself: OVL(benign, attack) = 0.33 in 2018. | VERIFIED (equals row number in 100% of rows) |
| `Flow ID`, `Src IP`, `Dst IP`, `Src Port` | Identity, not behaviour. The testbed's attacker and victim addresses are fixed. | DOCUMENTED |
| `Timestamp` | Used only to order rows and assign windows, never as a value. Time of day still carries signal (OVL 0.70 in 2018, 0.85 in 2017), because attacks are scheduled. | VERIFIED |
| `Label`, `Attempted Category` | These are the targets. | — |
| File, day or scenario identity | Each day hosts specific attacks. | VERIFIED (`split_design_coverage.csv`) |

## 2. Features that need review before use

| Feature(s) | Issue | Rule |
|---|---|---|
| `Fwd/Bwd Header Length` | int16 export overflow in the improved release (`reports/dataset_audit_report.md` §5.2) | **Exclude** |
| `Dst Port`, `Protocol` | Shortcut candidates. `Dst Port` OVL is 0.103 (2018) and 0.157 (2017); D'hooge et al. 2022 show that the port alone separates NIDS datasets. Both are also used in the labelling rules. | Allowed in the main feature set; **ablated** in E5 |
| `FWD/Bwd Init Win Bytes` | OVL 0.141 / 0.150 (2018). The "not observed" sentinel changed between releases. | Ablated in E5 |
| Columns used by the labelling rules | 2017: `Dst Port`, `Flow Duration`, `Fwd Packet Length Max`, total packets and lengths. 2018: also `Fwd/Bwd RST Flags` and `Protocol`. Some labels, Attempted in particular, are **defined** by these values (e.g. "no payload"). A model can relearn the rule. | Report it; interpret Attempted-versus-attack separation as **by construction**, not as detection skill |
| Packet-length features (`Packet Length Max`, `Bwd Packet Length Max`, …) | The lowest OVL of all: about 0.09 in both improved releases | No rule change. Report per-day results so that a single-feature shortcut is visible. |

Single-feature separability is **stronger in the improved releases than in the originals**: the best non-context feature has OVL ≈ 0.09 against 0.31–0.39 (`feature_separability.csv`). Two explanations are possible, and they have **not** been told apart (HYPOTHESIS):

1. The corrected flows are cleaner.
2. Labelling with feature filters makes classes more homogeneous.

## 3. Look-ahead leakage from flow-level features (H7)

**The problem.** A CICFlowMeter row summarises a flow over its **whole** life, up to the 120 s flow timeout, but its `Timestamp` is the flow's **start**. 22–38% of flows last longer than a 2 s window (VERIFIED, `reports/temporal_feasibility.md` §3). If such a row's totals (duration, bytes, packets, IATs, flags) are added to the window where the flow starts, that window's features contain **up to 120 s of future** traffic.

**Rule (`window_feature_policy` in the YAML).**

| Variant | Definition | Role |
|---|---|---|
| `ended_flows_only` | A flow contributes to window *t* only if start + `Flow Duration` ≤ end of *t* | **Default** |
| `flow_start_counts_and_header_features` | Counts of flow starts, plus features that are known at the first packet | Alternative |
| `lag_all_features_by_flow_timeout` | Every window feature lagged by ≥ 120 s | Conservative alternative |
| start-attributed totals | Totals assigned to the start window | **Forbidden**, except as the E7 ablation that measures the leak |

## 4. Split candidates: evidence (`split_design_coverage.csv`, `split_duplicate_leakage.csv`, `split_family_leakage.csv`)

**How every split was evaluated.**

- Each split was applied to all 65.3M improved rows.
- **Exclusion:** the 2,609 stray rows of `Friday-23-02-2018` (21–22 Feb) are excluded and counted (`row_exclusions`).
- **Embargo:** within-day splits drop rows whose flow start is within ±130 s of a cut. 130 s = the 120 s flow timeout + 5 × 2 s, the longest horizon.

### 4.1 Results

| Protocol | Dataset | Test attack flows | Test families absent from train | Test rows seen in train | Test attack flows seen in train | … in train + val |
|---|---|---:|---|---:|---:|---:|
| **P0** random rows (70/15/15) | 2017 | 76,200 | none | **15.6%** | **25.8%** | 27.6% |
| P0 | 2018 | 530,038 | none | **30.0%** | 1.2% | 1.2% |
| **P1** within day, time fractions 60/20/20 | 2017 | 121,576 | all 5 (DDoS, Infiltration ×2, Heartbleed, SSH) | 8.1% | 0% | 10.2% |
| P1 | 2018 | **0** | — | 28.4% | — | — |
| P1b within day, flow quantiles 60/20/20 | 2017 | 76,800 | 3 of 5 (DDoS, Heartbleed, SSH); the Infiltration classes are present | 9.5% | 2.1% | 5.3% |
| P1b | 2018 | 15,184 | 2 of 5 (SSH-BruteForce, Web SQL); Botnet Ares, NMAP and C2 are present | 28.8% | 7.1% | 7.8% |
| **P2** by day (2017: Mon–Wed / Thu / Fri) | 2017 | 254,946 | all 3 (Botnet, DDoS, Portscan) | 5.9% | 0% | 2.9% |
| P2 (2018: 14–21 Feb / 22–23 Feb / 28 Feb–2 Mar) | 2018 | 232,584 | all 4 (Botnet, 3 infiltration stages) | 26.6% | 0.01% | 0.01% |
| **P3** forward chain, test 21 Feb | 2018 | 1,084,023 | HOIC; LOIC-UDP (in val day 20 Feb) | 25.4% | 0% | 0% |
| P3, test 23 Feb | 2018 | 158 | 3 web attacks (in val day 22 Feb) | 30.7% | 0% | 0% |
| P3, test 1 Mar | 2018 | 39,834 | 3 infiltration stages (in val day 28 Feb) | 27.5% | 0.04% | **45.9%** |
| P3, test 2 Mar | 2018 | 142,921 | Botnet Ares | 26.1% | 0% | 0% |
| P3, test Fri (= P2) | 2017 | 254,946 | all 3 | 5.9% | 0% | 2.9% |

### 4.2 What the table shows (VERIFIED counts)

1. **Random rows (P0) leak attacks through port scans.**
   - In 2017, 25.8% of the test attack flows have an exact twin in training. Per family, those twins are **only** in Portscan (57%) and Infiltration – Portscan (55%); every other family has 0%.
   - In 2018 the same holds for NMAP Portscan (47%).
   - In 2018, 30% of **all** test rows are seen, mostly benign.
   - **P0 inflates scan detection and benign specificity.** It stays diagnostic only.
2. **Within-day chronological splits (P1) are not usable for these data.**
   - Attacks are scripted blocks at fixed times of day, so the time cut decides which attacks fall into which partition. In 2017, the train partition holds the morning families and the test partition the afternoon ones.
   - In 2018, the last 20% of each day's time span holds 834,247 rows and **no** attack flows, because traffic thins out after about 21:00 UTC.
   - **A first run, without the stray-row exclusion, reported 158 test attacks.** That was an artefact: the stray rows stretched `Friday-23-02`'s span, which pushed nearly all of 23 Feb into "test".
   - **Cutting at flow-count quantiles instead (P1b) puts attacks into the test partition** (76,800 and 15,184 flows), including families already seen earlier the same day. It has two costs:
     - The cuts fall inside attack blocks, so the ±130 s embargo removes 113,522 (2017) and 716,549 (2018) attack flows.
     - Training contains **later days** than parts of the test partition. The split is chronological within a day only, and leaks across days.

     P1b is useful as a "same scenario, later in the day" diagnostic, not as a primary protocol.
3. **Day-level splits (P2, P3) test only unseen attack types, apart from a few recurring families.**
   - **2017:** no family recurs on a later day, so P2 and P3 measure only generalisation to new attack types. The one exception is Friday's Portscan: 4.6% of its flows duplicate Thursday's Infiltration – Portscan.
   - **2018:** three families recur, **on the day immediately before the test day**: LOIC-UDP (20 → 21 Feb), the web attacks (22 → 23 Feb), and the infiltration stages (28 Feb → 1 Mar). In every P3 fold the recurring family is therefore in the **validation** day, not in training. It is "seen" only if the final model is refit on train + val.
   - **After refitting on train + val,** only the 1 Mar NMAP Portscan has exact twins (46%). LOIC-UDP and the web attacks have **none**, so a correct prediction for them is generalisation within a family, not memorisation.
4. **Benign duplicates are everywhere.** 25–31% of test rows in every 2018 day-level split have a twin in training, almost all benign. This cannot be avoided. It inflates benign specificity equally across models. Report a de-duplicated test score next to the raw one.

## 5. Recommended protocol (`recommended` in the YAML)

| Role | Splits | What it answers |
|---|---|---|
| **Primary, 2018** | P3 forward-chaining folds: test 21 Feb, 23 Feb, 1 Mar, 2 Mar. Refit on train + val after model selection. Report **both** the train-only and the train+val model. | "Does the model predict tomorrow's attacks from the past?" Score the recurring families (LOIC-UDP, web, infiltration) **separately** from the unseen ones (HOIC, Botnet Ares). |
| **Primary, 2017** | P3 test Fri (identical to P2) | Unseen-family generalisation only. 2017 has no recurring family. |
| **Robustness** | Leave-one-day-out over the attack days; cross-dataset transfer (train 2018 improved, test 2017 improved, shared features, coarse families) | Scenario sensitivity; transfer |
| **Diagnostic only** | P0 random rows; P1 and P1b within-day | The size of the optimism that random splits create (H2) |

**Fixed rules for every split.**

- Windows never cross a file or day.
- The 130 s embargo applies around every within-day cut.
- Configured exclusions are applied and counted.

## 6. Fitting and thresholds (`preprocessing_fit_policy`, `refit_on_train_plus_val`)

- **Fit on train only:** scalers, imputers, quantile bins, feature selection and class weights are fit on **train** and applied unchanged to val and test.
- **Thresholds:** decision thresholds and hyperparameters are chosen on **val**, never on test.
- **Refit on train + val** is allowed only after they are frozen. Both results are reported.
- **Non-finite rate values:** 5 rows (2017) and 57 rows (2018) are imputed or excluded, and the count is reported.

## 7. Attempted policy (`attempted_policy`)

**The problem.**

- Attempted flows are 11,979 (2017) and 306,237 (2018). In 2018, 298,874 of them are FTP-BruteForce attempts: 298,844 in category 1 ("port closed") and 30 in category 4.
- They are separable from attacks by construction. In 2018, the median single-feature OVL(attack, attempted) is 0.044.

**Rule.**

- **Primary:** Attempted is its own class for analysis. For the binary target it counts as **benign**: "no successful attack activity".
- **Ablations** (E4): Attempted counted as attack; Attempted excluded (counted).

## 8. Irreducible error from label conflicts (`label_conflict_composition.csv`)

Rows whose feature vectors are identical but whose labels differ cannot all be classified correctly.

| Dataset | Label pair | Groups | Rows | Rows in the minority label (minimum unavoidable error) |
|---|---|---:|---:|---:|
| 2017 | `Infiltration – Portscan` (Thursday) vs `Portscan` (Friday) | 4,368 | 14,118 | 4,939 |
| 2017 | `BENIGN` vs `Portscan` | 7 | 22 | 7 |
| 2018 | `BENIGN` vs `FTP-BruteForce – Attempted` | 9 | 263,736 (263,676 Attempted, 60 benign) | 60 |
| 2018 | `BENIGN` vs `Infiltration – NMAP Portscan` | 4 | 36 | 5 |

**Meaning.** The minority rows are the floor on the errors of any classifier that sees only these features. Report this floor next to every per-class result.

- **2017.** The floor is multi-class: identical scan probes are labelled by scenario (Thursday's infiltration versus Friday's port scan). A behaviour-level target should merge the two into one `portscan` family. The benign-versus-attack floor is only 7 rows.
- **2018.** 263,772 rows sit in conflict groups, but the binary floor is only **65 rows**. The groups are large blocks of identical failed FTP connection attempts that happen to match 60 benign flows.

## 9. Metrics and baselines (`metrics`, `baselines_before_any_deep_model`)

**Metrics.**

- Per-class precision, recall and F1.
- Macro-F1, and PR-AUC per class.
- **False alerts per hour**, and recall at 1 and 10 false alerts per hour (operational view).
- For early warning: lead time and onset recall, computed only on episode onsets that have ≥ *h* benign windows before them.
- Accuracy alone is forbidden, because benign is 75–94% of flows.

**Uncertainty.**

- Bootstrap 95% CIs over days or episodes, not over windows, because windows are autocorrelated.
- 5 seeds wherever training is stochastic.

**Baselines, in order, before any deep model.**

1. Majority class.
2. **Persistence**, in two forms. Oracle persistence explains 67–73% (2017) and 91–93% (2018) of next-window positives.
   - **Detector persistence** (the fair baseline): predict for *t*+*h* what the current-window (*h* = 0) detector outputs at *t*.
   - **Oracle persistence** (*ŷ*(*t*+*h*) = true *y*(*t*)): an **upper bound** only. True labels are not known online, so a model compared only with the oracle looks worse than it is, and one compared with nothing looks better.
3. Stratified random.
4. Logistic regression and gradient-boosted trees or random forest on window aggregates.
5. A lagged-aggregate temporal baseline.

Skill is reported **relative to detector persistence**, with the oracle as the bound. It is also reported separately on windows where *t* is benign and on true onsets.

## 10. Checklist before any result is reported (Phase 8)

1. The split appears in `configs/evaluation_protocol.yaml`, and its coverage and duplicate rows are cited.
2. No never-input column, and no file, day or time-of-day identity, among the features.
3. Window features follow `window_feature_policy`, and E7 measures what start attribution would add.
4. All statistics fit on train, and thresholds on val.
5. Detector persistence, oracle persistence and the simple baselines are reported on the same windows.
6. Per-day and per-family results, with CIs and counts. Families with fewer than about 100 flows or one episode are reported as counts only.
7. Seen and unseen families are scored separately, and the de-duplicated test score is reported.
8. Every exclusion is counted (stray rows, non-finite rows, the Attempted policy).
9. The release is named precisely (CNS2022 improved, post-publication files; SHA-256 in `data/manifests/checksums_sha256.csv`).
