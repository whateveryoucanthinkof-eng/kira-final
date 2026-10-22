# Phase 7: Research questions and falsifiable hypotheses

**Status: PROPOSED.** Nothing here has been tested, and no model has been trained. Phase 8 (baselines and modelling) starts only after the user has reviewed the audit.

Evidence labels: **VERIFIED**, **DOCUMENTED**, **HYPOTHESIS**, **UNRESOLVED** (defined in `reports/dataset_provenance.md`).

- **Experiments:** `configs/experiment_matrix.yaml`.
- **Protocol:** `configs/evaluation_protocol.yaml` and `reports/evaluation_protocol.md`.
- **Prior work:** `reports/literature_review.md`: a scoping check (§1–4) and a systematic citation search (§5; decisions in `results/literature/manual_screening.csv`).

## 1. The task, in standard terms

This project uses the taxonomy of Husák et al. (IEEE COMST 2019): attack *projection*, attack *prediction*, and security-situation *forecasting*.

**The primary task is attack prediction on a network-state time series.**

- The capture is cut into fixed 2 s windows.
- The question is whether any attack flow will **start** in window *t + h*, for *h* = 1…5 (2–10 s ahead).
- The input is only what has been observed by the end of window *t*.

**This is not "early detection" in the flow-classification sense.** That literature classifies one flow from its first packets (`reports/literature_review.md` §2.4). Results from those papers are not comparable with ours, and we will not claim they are.

**Secondary tasks:**

1. Current-window detection (*h* = 0), used as a reference point.
2. Attack-onset forecasting, scored only on true episode onsets. There are very few of them (§3).

## 2. Research questions

| RQ | Question |
|---|---|
| **RQ1** | On the CNS2022 corrected releases, how much of the next-window attack state can be predicted **beyond persistence**, under a leakage-aware temporal protocol? |
| **RQ2** | How much do evaluation-design choices change that answer? The choices are: the split, how flow-level features are attributed to windows, and whether known shortcut features are used. |
| **RQ3** | How much do the CNS2022 corrections themselves change measured temporal performance? The corrections are relabelling, the new "Attempted" class, and regenerated flows. |
| **RQ4** | Does a temporal model trained on one corrected release transfer to the other? |

## 3. Hypotheses

Every hypothesis is falsifiable and maps to one experiment. The "audit evidence" column holds measured facts (VERIFIED); the hypothesis itself is untested.

| ID | Hypothesis | Audit evidence that motivates it | Experiment | Falsified if | Novelty |
|---|---|---|---|---|---|
| **H1** (RQ3) | Under identical pipelines, window-level performance differs between the original and improved CIC-IDS-2017. | Label families change by factors of about 0.5 (`label_family_comparison.csv`). The flow count falls by 25.8%. 11,979 Attempted flows are new. Feature-identical label conflicts change (`duplicates_by_file.csv`). | E3, 2017 only, 60 s windows | The 95% CI of the difference includes 0 | HYPOTHESIS: possible gap. CNS2022 measured static per-attack effects only, and the systematic search found no temporal comparison of releases. |
| **H2** (RQ2) | Random-row splits overstate performance relative to day-chronological and forward-chaining splits. | Under the random split, 15.6% (2017) and 30.0% (2018) of evaluation rows have a feature vector already in training (`split_duplicate_leakage.csv`). | E1 | The gap CI includes 0 for both datasets | **Not novel** (Arp et al. 2022; on these datasets L02–L04 in `manual_screening.csv`). A supporting result only. |
| **H3** (RQ4) | Training on improved 2018 and testing on improved 2017 loses much of the within-dataset performance. | The schemas are identical (91 columns). 11 attack families share a name across the datasets: botnet, DoS (4 types), FTP/SSH brute force, infiltration, and 3 web attacks. DDoS maps only at the coarse "ddos" level. Heartbleed and the 2017 PortScan have no 2018 counterpart (`configs/label_family_map.yaml`). Some shared families exist in improved 2018 only as Attempted flows, e.g. FTP brute force (`label_distribution_by_dataset.csv`). | E6 | Transfer is within the CI of within-dataset P2 performance | **Not novel** on the original or LycoS data (Cantone 2024; L03). It is HYPOTHESIS only for the CNS2022 releases under a temporal protocol. |
| **H4** (RQ1) | Next-window skill beyond persistence is small and falls with *h*. Onset recall is far below "next-window" recall. | Persistence explains 67–73% (2017) and 91–93% (2018) of next-window positives. There are 1,529–2,009 "onset-like" transitions per horizon, but only 24 and 38 true episode onsets at a 300 s gap (`reports/temporal_feasibility.md` §4–5). | E2 | Skill over persistence at *h* ≥ 1 is within the CI of *h* = 0, **or** onset recall is within the CI of overall next-window recall | The **task is not novel**: SENTINEL (L01, 2026) forecasts network-state windows on CSE-CIC-IDS2018. Separating persistence and within-episode recurrence from onset anticipation is a **HYPOTHESIS: possible gap**; it needs SENTINEL's full text (`reports/literature_review.md` §5.3). |
| **H5** (RQ3) | How Attempted flows are treated changes false alerts per hour and onset recall. | 11,979 (2017) and 306,237 (2018) Attempted flows. Category 2 artefacts precede some episodes by design. Single features separate Attempted flows from both other classes. In 2018 the median OVL(attack, attempted) over all features is 0.044, and OVL(benign, attempted) is 0.006 for `FWD Init Win Bytes`. So the chosen policy changes what a model has to learn (`feature_separability.csv`). | E4 | No metric changes beyond its CI | HYPOTHESIS |
| **H6** (RQ2) | Removing context and shortcut features (`Dst Port`, `Protocol`, `Init Win Bytes`) lowers day-held-out performance. | Single-feature overlap between benign and attack is small for `Dst Port` (OVL 0.103 in 2018 improved; 0.157 in 2017) and for `FWD/Bwd Init Win Bytes` in 2018 (0.141 / 0.150) (`feature_separability.csv`). | E5 | The drop CI includes 0 | **Not novel** as a claim (D'hooge 2022; CNS2022 Fig. 1; L04, L19). Run as a control. |
| **H7** (RQ2) | Attributing flow-level totals (duration, bytes, packets, IATs) to the window in which a flow **starts** inflates window-level scores, compared with using only flows that have **ended** by the window's end. | 23.9–30.7% (2017) and 22.3–38.1% (2018) of flows last longer than one 2 s window. Flows last up to 120 s, the flow timeout (`reports/temporal_feasibility.md` §3). | E7 | The difference CI includes 0 at every *h* | HYPOTHESIS: possible gap. Related evidence: models trained on complete flows degrade on partial flows (L11, per-flow). A study of flow timeouts (L12) is known only by its title. No work found measures this in window forecasting. |

## 4. What the evidence does and does not support

**Supported by the audit (VERIFIED):**

- **The data allow a 2 s window study.** The improved releases have UTC microsecond timestamps, consistent with every documented labelling window. Each day is nearly continuous, with no gap between flow starts over 130 s apart from the stray rows in `Friday-23-02-2018`.
- **The originals cannot support the same study.** Their clocks are 12-hour without AM/PM. The 2017 originals have minute resolution. 7 of the 10 2018 originals are capped at 1,048,575 rows.
- **Attacks are scripted blocks.** That is why persistence is a strong baseline and onsets are rare.

**Not supported, and it must not be claimed:**

- **Precision of results by attack family.** Most families occur in one episode on one day, so any per-family result is anecdotal.
- **Generalisation to real networks.** The data come from a testbed with scripted attacks (Flood et al. 2024, design smells).
- **Novelty.** The systematic search (`reports/literature_review.md` §5) found that **next-window network-state forecasting on CSE-CIC-IDS2018 is already published** (SENTINEL, a 2026 preprint), as are attack-trend forecasting and day-chronological evaluation. What remains a possible gap (HYPOTHESIS) is the **measurement**: persistence- and onset-controlled scoring (H4), the look-ahead from flow attribution (H7), the effect of the corrections (H1), and any temporal evaluation of the **corrected CSE-CIC-IDS2018**. Several of the closest works were read at abstract level only (§5.4).

## 5. Threats to validity, and how the protocol handles them

| Threat | Handling |
|---|---|
| **Temporal leakage**: random splits, overlapping windows, and flows spanning a cut | Day-level and forward-chaining splits; a 130 s embargo; windows never cross a file or day; random splits reported as a diagnostic only. |
| **Look-ahead in features** (H7) | Default to features from ended flows only. The start-attributed version is the ablation. |
| **Persistence masquerading as skill** | Persistence is a mandatory baseline. Scores are reported separately for windows where *t* is benign and for true onsets. |
| **Duplicates and label conflicts** | Feature-identical groups with conflicting labels are reported as irreducible error. Duplicate overlap across partitions is reported for every split. |
| **Shortcuts** (`Dst Port`, `id`, time of day, file identity) | `id`, IPs, ports, timestamps and file identity are never inputs. `Dst Port`, `Protocol` and `Init Win Bytes` are ablated. |
| **Few events** | Exact counts, bootstrap CIs over days or episodes, and 5 seeds. No per-family claims. |
| **Release ambiguity** | Every result names the release ("CNS2022 improved, April 2023 post-publication files", SHA-256 in `data/manifests/checksums_sha256.csv`). |
