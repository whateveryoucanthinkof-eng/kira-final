# Literature review: scoping check and systematic citation search (Phase 7)

**Status, 2026-10-19.** Two stages are done:

1. A 13-query **scoping** search (§1–4).
2. A **systematic forward-citation search with logged keyword queries** (§5), which supersedes the scoping gap assessment.

Novelty statements are still **HYPOTHESIS**: several of the closest works could only be read at abstract level (§5.4).

## 1. Search log

| # | Date | Tool / mode | Query |
|---|---|---|---|
| 1 | 2026-10-19 | web search, standard | `Engelen Rimmer Joosen "Troubleshooting an Intrusion Detection Dataset" CICIDS2017` |
| 2 | 2026-10-19 | web search, standard | `Lanvin errors in the CICIDS2017 dataset significant differences in detection performances` |
| 3 | 2026-10-19 | web search, standard | `"Dos and Don'ts of Machine Learning in Computer Security" Arp data snooping spurious correlations` |
| 4 | 2026-10-19 | web search, standard | `survey attack projection prediction forecasting cyber security Husák` |
| 5 | 2026-10-19 | web search, extended | `network intrusion detection temporal train test split versus random split overestimation CIC-IDS2017` |
| 6 | 2026-10-19 | web search, standard | `cross-dataset generalization CIC-IDS2017 CSE-CIC-IDS2018 machine learning intrusion detection transfer` |
| 7 | 2026-10-19 | web search, standard | `"Error Prevalence in NIDS datasets" improved CIC-IDS-2017 dataset Liu Engelen used evaluation 2024` |
| 8 | 2026-10-19 | web search, standard | `D'hooge contaminating effect of metadata feature inclusion machine-learned network intrusion detection` |
| 9 | 2026-10-19 | web search, extended | `early prediction of network attacks before onset time-window forecasting flows deep learning intrusion CIC-IDS` |
| 10 | 2026-10-19 | web search, standard | `Rosay LycoS-IDS2017 corrected CIC-IDS2017 comprehensive analysis` |
| 11 | 2026-10-19 | web search, standard | `Flood Engelen 2024 "Bad Design Smells in Benchmark NIDS Datasets"` |
| 12 | 2026-10-19 | web search, extended | `"improved CIC-IDS2017" OR "corrected CIC-IDS2017" distrinet dataset temporal sequence model evaluation` |
| 13 | 2026-10-19 | web search, standard | `network security situation forecasting time series attack rate prediction next window CSE-CIC-IDS2018 LSTM` |

The release site and the CNS2022 code repository were also read directly (see `reports/dataset_provenance.md`).

**Reading depth.**

- **Full text:** only the CNS2022 paper (local PDF), the CNS2022 labelling code, and the release pages.
- **Search results only:** everything else, i.e. abstracts, metadata and search-engine summaries.

Claims below are limited to what those levels support. Before any of them is cited in the paper, the full text must be read.

## 2. Sources and what they establish

### 2.1 Dataset errors and corrected releases (the basis of this project)

| Source | Read at | What it establishes (relevant here) |
|---|---|---|
| L. Liu, G. Engelen, T. Lynar, D. Essam, W. Joosen. *Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018.* IEEE CNS 2022, pp. 254–263, DOI 10.1109/CNS56114.2022.9947235 | full text | See §3. |
| G. Engelen, V. Rimmer, W. Joosen. *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study.* IEEE S&P Workshops 2021, DOI 10.1109/SPW53761.2021.00009 ([lirias](https://lirias.kuleuven.be/retrieve/713070)) | abstract | Problems in traffic generation, flow construction, feature extraction and labelling of CIC-IDS2017. The fixes change more than 20% of traces, and ML benchmarks improve. This is the CNS2022 paper's reference [11] and the source of the FIN/RST fixes in the CICFlowMeter fork. |
| M. Lanvin et al. *Errors in the CICIDS2017 Dataset and the Significant Differences in Detection Performances It Makes.* CRiSIS 2022 (Springer, 2023, pp. 18–33) ([HAL hal-03775466](https://hal.archives-ouvertes.fr/hal-03775466)) | abstract | Packet misordering, packet duplication, and attacks performed but not labelled in CIC-IDS2017, with a measured effect on supervised IDS evaluation. (The same author proposed, then had reverted, a "traffic duplication removal" change to the CNS2022 code, verified in the repository history.) |
| A. Rosay, E. Cheval, F. Carlier, P. Leroux. *Network Intrusion Detection: A Comprehensive Analysis of CIC-IDS2017.* ICISSP 2022, pp. 25–36 ([SciTePress](https://www.scitepress.org/Papers/2022/107740/)) | abstract | Flow-extraction problems in CIC-IDS2017, the LycoSTand extractor, and the LYCOS-IDS2017 dataset. Artefacts also appear in other CICFlowMeter-based datasets. **A second, independent corrected release exists**, so "the improved CIC-IDS2017" is ambiguous unless the CNS2022 release is named explicitly. |
| R. Flood, G. Engelen, D. Aspinall, L. Desmet. *Bad Design Smells in Benchmark NIDS Datasets.* IEEE EuroS&P 2024 ([IEEE Xplore](https://ieeexplore.ieee.org/document/10629000)) | abstract | Six recurring dataset-design "smells" across 7 benchmarks, linked to low diversity, ambiguous labelling and undefined generalisation criteria, with examples of experimental bias. |

### 2.2 Evaluation pitfalls, leakage and shortcuts

| Source | Read at | What it establishes |
|---|---|---|
| D. Arp et al. *Dos and Don'ts of Machine Learning in Computer Security.* USENIX Security 2022 ([arXiv 2010.09470](https://arxiv.org/pdf/2010.09470)) | search summary | Ten pitfalls are common across 30 top-venue papers. They include **data snooping**, with *temporal snooping* (ignoring time dependencies) as a named sub-case, and **spurious correlations**. This is the canonical citation for our split protocol. |
| L. D'hooge, M. Verkerken, B. Volckaert, T. Wauters, F. De Turck. *Establishing the Contaminating Effect of Metadata Feature Inclusion in Machine-Learned Network Intrusion Detection Models.* DIMVA 2022, LNCS 13358, pp. 23–41, DOI 10.1007/978-3-031-09484-2_2 ([imec](https://imec-publications.be/handle/20.500.12860/40718)) | abstract | **Destination port alone** separates 10 NIDS datasets with 70–100% accuracy on class-balanced tests. The authors recommend excluding metadata features. A follow-up at PST 2022 covers non-metadata contaminant features. |
| *Do Transformers Actually Help Intrusion Detection? A Temporal Sequence Evaluation on CIC-IDS2017* (preprint, [arXiv 2606.11098](https://arxiv.org/abs/2606.11098), 2026) | search summary | Benchmarks nine sequence architectures under random and leakage-free splits. Random splits overestimate performance, and overlapping sliding windows leak. **It is unclear which CIC-IDS2017 release was used.** |
| *A Leakage-Aware Evaluation of a Multi-Scale Attention TCN for Binary NID* ([MDPI Mathematics, DOI 10.3390/math14183357](https://doi.org/10.3390/math14183357)) | search summary | A day-level holdout lowers performance for all models evaluated on CIC-IDS2017. |

Unrefereed GitHub projects reporting near-perfect F1 under random splits and about 0.54 F1 on held-out days were also found. They agree in direction but are **not cited as evidence**.

### 2.3 Cross-dataset generalisation

| Source | Read at | What it establishes |
|---|---|---|
| Cantone et al. *On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection* ([arXiv 2402.10974](https://arxiv.org/html/2402.10974v1), 2024) | search summary | Performance within a dataset is near-perfect, while cross-dataset performance is near chance for most pairs among CIC-IDS2017, CSE-CIC-IDS2018 and the LycoS versions. They release LycoS-Unicas-IDS2018, a further corrected 2018 variant. |
| NDSS 2023 poster, paper 4547 ([PDF](https://www.ndss-symposium.org/wp-content/uploads/2023/02/NDSS2023Poster_paper_4547.pdf)) | search summary | Recommends evaluating across distinct datasets with compatible features; reports about a 30% average AUROC drop. |
| Şengül & Kılıç, SHAP-guided feature selection for cross-dataset NIDS ([repository record](https://ada.atilim.edu.tr/items/d25563f0-322c-4384-b748-fe9d5695f1af)) | repository record | Macro-F1 of about 0.90 on CIC-IDS2017 drops to about 0.12 on CSE-CIC-IDS2018. **Publication details unverified.** |

### 2.4 Attack prediction, forecasting and early detection

| Source | Read at | What it establishes |
|---|---|---|
| M. Husák et al. *Survey of Attack Projection, Prediction, and Forecasting in Cyber Security.* IEEE COMST 2019, DOI 10.1109/COMST.2018.2871866 ([MUNI](https://www.ics.muni.cz/en/research/publications/1434138)) | abstract | A taxonomy: attack projection (the attacker's next step), attack prediction (upcoming intrusions), and security-situation forecasting (network-wide). It covers discrete models (attack graphs, Bayesian networks, Markov models) and continuous ones (time series, grey models), and discusses evaluation. **This is the vocabulary our targets must use.** |
| M. Husák, V. Bartoš, P. Sokol, A. Gajdoš. FGCS 2021, DOI 10.1016/j.future.2020.10.006 (title not retrieved) | search summary | Three predictive methods compared on an alert-sharing platform. Time-series forecasting of attack rates is lightweight and accurate but gives no detail about individual events. |
| Ahmed, Azad, Asyhari. *Rapid Forecasting of Cyber Events Using Machine Learning-Enabled Features.* Information 15(1):36, 2024 ([MDPI](https://www.mdpi.com/2078-2489/15/1/36)) | search summary | Time-series forecasting of cyber events built from **CSE-CIC-IDS2018 (original release)**, with SMOreg, linear regression and LSTM compared. The closest prior work to "next-window" forecasting on these data. |
| *Early Detection of Network Attacks Using Deep Learning* ([arXiv 2201.11628](https://arxiv.org/pdf/2201.11628)); *Early Network Intrusion Detection Enabled by Attention Mechanisms and RNNs*, IEEE TIFS 2024, DOI 10.1109/TIFS.2024.3441862; multidomain transformer for early detection ([arXiv 2309.01070](https://arxiv.org/pdf/2309.01070)) | search summary | Here "early" means classifying a **flow from its first packets**, i.e. earliness within a flow. That is a different task from forecasting future attack activity in a network-state time series. |
| *Early Prediction of Tactical Transitions in Cyber Attack Processes Through Network Flows* ([ResearchGate](https://www.researchgate.net/publication/415182166_Early_Prediction_of_Tactical_Transitions_in_Cyber_Attack_Processes_Through_Network_Flows)) | search summary | Zeek flows are aggregated into fixed windows to forecast the next ATT&CK tactic. The best macro-F1 is 0.50 at 10-minute windows, and an LSTM did not beat static models. This is a realistic expectation-setter for stage forecasting. |

## 3. What the CNS2022 paper establishes, and what it leaves open (full text)

**Established (DOCUMENTED):**

- **Error rates.** Published labels are wrong for 6.67% (2017) and 7.53% (2018) of flows (Table V). Several attacks have corruption above 75% (Table III).
- **Feature-only ambiguity.** Some flows are identical once identifiers are removed but carry different classes (Table IV).
- **Tool and data fixes.** The CICFlowMeter fixes are flow termination (FIN/RST), Bulk features, the TCP Segmentation Offload issue, ICMP support, RST counts, total TCP duration, and UTC timestamps with microsecond precision. The datasets were regenerated from the PCAPs and the labelling logic was released.
- **Effect on learning.** With Random Forest, the corrected data changes the learned feature representations: the reliance on `Dst Port` and `Init Win Bytes` drops. With MLPs, training is more stable.
- **Automated relabelling.** Confident Learning and O2U-Net do **not** recover the corrections.
- **Limitations stated by the authors.** Problems at the PCAP level remain: the DoS Hulk attack was ineffective. Small residual errors are possible, and post-publication corrections were expected. Those fixes happened (repository commits of March–April 2023, VERIFIED).

**Not addressed in the paper:**

- Any **temporal** evaluation, whether next-window prediction, onset forecasting, or sequence models.
- **Chronological or day-held-out** splits. Its experiments are per-attack classification and training-loss analysis.
- **Cross-dataset** transfer between the corrected releases.
- The **class definition for "Attempted"** flows in downstream tasks.
- Whether the regenerated flow semantics (FIN/RST termination, 120 s flow timeout, 5 s activity timeout) change **window-level** statistics.

## 4. Gap assessment (scoping stage; superseded by §5.3)

The systematic search (§5) found direct prior work on next-window forecasting on CSE-CIC-IDS2018. The row about next-window prediction below is therefore **no longer a candidate gap**. The table is kept as a record of the scoping stage. Each statement is labelled with its evidence level.

| Candidate contribution | Prior work found | Status |
|---|---|---|
| "Random splits overestimate performance compared with temporal or day-held-out splits" | Arp 2022 (general principle); the 2026 preprint and the MDPI TCN paper (CIC-IDS2017, release unclear); GitHub projects | **Not novel as a general claim.** It can be a supporting result, but not a contribution. |
| "Models do not transfer between CIC-IDS2017 and CSE-CIC-IDS2018" | Cantone 2024; the NDSS 2023 poster; Şengül & Kılıç | **Not novel** on the original or LycoS data. Only "transfer between the **CNS2022** corrected releases under a temporal protocol" is not covered by the sources found. HYPOTHESIS. |
| "Metadata/port features are shortcuts" | D'hooge (DIMVA 2022); CNS2022 Fig. 1 | **Not novel.** Reproduce as a control, not as a contribution. |
| Next-window (2 s) attack-state prediction and onset forecasting on the **CNS2022 corrected releases**, using their UTC microsecond timestamps, with leakage-aware temporal protocols (flow-timeout embargo, no cross-day windows) | No source found in 13 queries. The nearest are Ahmed 2024 (original 2018, coarser forecasting), the 2026 preprint (sequence classification, release unclear), and the tactic-transition paper (other data). | **HYPOTHESIS: possible gap.** Needs a systematic search first. |
| How the corrections (relabelling, the "Attempted" split, regenerated flows) change **temporal** task difficulty and measured early-warning performance | The CNS2022 paper measures static per-attack effects only | **HYPOTHESIS: possible gap.** |

The steps this stage named as required (a citation search of CNS2022 and Engelen 2021, keyword queries, and logged decisions) were carried out in §5. The remaining full-text reading is listed in §5.4.

## 5. Systematic search (2026-10-19)

### 5.1 Method

**Forward citation tracking** of two seed papers in two open bibliographic databases:

| Seed | DOI |
|---|---|
| CNS2022 (Liu, Engelen et al.) | 10.1109/CNS56114.2022.9947235 |
| Engelen et al. 2021 | 10.1109/SPW53761.2021.00009 |

- **Code:** `python -I src/lit/citation_search.py fetch`, then `screen`.
- **Raw responses:** saved verbatim in `references/literature_search_2026-10-19/raw/`. Every request is in `query_log.csv`.

| Source | CNS2022 citing works | Engelen 2021 citing works |
|---|---:|---:|
| OpenAlex | 125 (reported total 125) | 191 (reported total 191) |
| Semantic Scholar | 154 | 231 |
| **Unique after merging** (DOI, then normalised title) | **197** | **289** |

That is **421 unique citing works**; 65 cite both seeds.

**Keyword search.** 14 logged OpenAlex title/abstract queries (`python -I src/lit/citation_search.py search`; the list is `KEYWORD_QUERIES` in the script):

- "attack forecasting"; "attack prediction" with time series; "next window"; "early warning"; "network security situation" forecasting;
- CIC-IDS combined with forecasting, temporal split or chronological split;
- "Distrinet-CIC-IDS2017"; "improved" and "corrected CIC-IDS2017";
- attack onset prediction.

Results: `results/literature/keyword_search_results.csv`.

**Screening.**

1. **Keyword screen (transparent).** Regex groups for *temporal*, *dataset quality* and *evaluation* terms are applied to title + abstract (`TERMS` in the script). Tiers among the 421 citing works:

   | Tier | Meaning | Works |
   |---|---|---:|
   | A | temporal + (quality or evaluation) | 45 |
   | B | temporal only | 56 |
   | C | quality or evaluation only | 106 |
   | X | none | 214 |

   104 works have no abstract in either index.
2. **Manual review.** All tier A and B titles and abstracts, all tier C titles, the 93 titles in tiers C and X that have no abstract, and the keyword hits on CIC data were reviewed by hand.
   - The 21 works that bear on H1–H7 are recorded in `results/literature/manual_screening.csv`, with read depth, dataset release, task, split, decision and reason.
   - Every other screened work is **excluded**: per-flow classification, other datasets, or adversarial, federated or other topics with no bearing on H1–H7.
3. **Full-text attempts.**
   - arXiv 2606.11098 was read (HTML).
   - Zenodo (SENTINEL) and Preprints.org refused automated download (HTTP 403). They were not retried by other means.
   - The IEEE papers (ICDSCA 2025, CICN 2025) are behind a paywall.
   - The IDS2Eval paper itself was not found; only its artifact record was.
4. **Supporting web lookups.**
   - 3 web searches: IDS2Eval; "Stream Assembly …"; "Detecting Attacks or Memorizing Artifacts".
   - 3 fetches: Zenodo record 22212693; arXiv 2606.11098 (abstract and HTML); Preprints.org 202606.0903 (returned 403).

### 5.2 What the systematic search found (`manual_screening.csv`)

| ID | Work | What it does | Release | Read at |
|---|---|---|---|---|
| L01 | **SENTINEL** (Shahane et al., Zenodo preprint, 2026) | **Network-state forecasting.** An 8-window history of 21 behavioural features feeds an LSTM "world model" that forecasts compromise up to 20 s ahead on the **CSE-CIC-IDS2018 infiltration** scenario. Recall 60.6% at 5% FPR, against 13.5% for logistic regression. | not stated | abstract + record page |
| L02 | Drift-robust evaluation on CSE-CIC-IDS2018 (IEEE ICDSCA 2025) | **Day-based split** (days 1–6 / 7–8 / 9–10), SOC false-positive budgets, **false alarms per hour**, hourly analysis. Cites CNS2022. | not stated | abstract |
| L03 | "The Evaluation Protocol Is the Hidden Variable" (preprint, 2026) | Random versus chronological split on CSE-CIC-IDS2018: macro-F1 about 0.8 → about 0.02. Cross-dataset transfer to CIC-DDoS2019 fails. | not stated | abstract |
| L04 | "Detecting Attacks or Memorizing Artifacts?" (2026, artifact record) | CIC-IDS2017 with Mon–Thu training, Friday test, near-duplicate removal, and `Dst Port` isolated. Attack recall collapses. | not stated | artifact description |
| L05 | IDS2Eval (2026, artifacts) | A falsification-oriented audit of 7 benchmarks **and the corrected CIC-IDS2017 release** | corrected 2017 | artifact description |
| L06 | Moczkodan & Ragab, arXiv 2606.11098 (2026) | Flow windows per conversation, used to classify the **current** flow. Padding and split matter more than the architecture. | **original** 2017 (2,827,677 flows) | full text (HTML) |
| L07–L09, L20, L21 | CICN 2025; Information 2024; PST 2019 (HMM next state); KBS 2026; CONIT 2025 | **Forecasting** of attack trends, event counts, features or QoS, and next-state prediction, on CSE-CIC-IDS2018 or CIC-IDS2017 | original or not stated | abstract |
| L10 | "Stream Assembly Is an Uncontrolled Treatment" (arXiv 2605.24696) | Re-ordering or pooling captures changes the test composition and reverses model rankings on CICIDS2017 | not stated | abstract |
| L11 | Complete versus partial flows (EuroS&PW 2025) | Models trained on complete flows lose up to 30% precision and recall on partial flows; about 7 packets are needed | not stated | abstract |
| L12 | "Flow timeout matters" (2024) | Effect of active and idle flow timeouts on ML NIDS | — | **title only** |
| L16–L18 | SPQ-AT (2026); contrastive + BGMM (2025); adversarial robustness benchmark (2024) | **Use the corrected CIC-IDS2017** ("Distrinet-CIC-IDS2017", "NewCICIDS") for **per-flow** tasks | corrected 2017 | abstract |

L13–L15 and L19 (surveys, and evidence from other datasets) are in the CSV only.

At abstract level:

- No work found uses the **corrected CSE-CIC-IDS2018** for any temporal task.
- No work found uses either corrected release for forecasting.

### 5.3 Revised gap assessment

| Candidate contribution | Prior work | Status |
|---|---|---|
| Next-window / network-state **attack forecasting** on CIC data | L01 SENTINEL (2018 infiltration, ≤ 20 s ahead); L07–L09, L20, L21 | **Not novel as a task.** Do not claim it. |
| Random versus chronological or day split gap; false alarms per hour; day-held-out evaluation with de-duplication | Arp 2022; L02, L03, L04, L15 | **Not novel.** Supporting result only (H2). |
| Cross-dataset failure | Cantone 2024; L03 | **Not novel** (H3). Run as a control. |
| Port and timestamp shortcuts | D'hooge 2022; L04, L19 | **Not novel** (H6). Run as a control. |
| An audit of the corrected releases | IDS2Eval (L05) audits the corrected **CIC-IDS2017**. CNS2022 itself documents its fixes. | **Partly preceded.** Our specific findings concern the **2018** corrected release, or compare the originals with the corrected releases. They may be new, but this is UNRESOLVED until IDS2Eval is read. The findings are: the int16 header-length overflow; the stray 21–22 Feb flows in `Friday-23-02-2018`; the 12-hour clocks of both original releases; and the conflict-group floors. |
| **Separating forecasting skill from persistence and within-episode recurrence**, with true episode onsets scored separately (H4) | SENTINEL reports logistic regression as its baseline (abstract). L14 notes weak temporal validation in general. | **HYPOTHESIS: possible gap.** Needs SENTINEL's full text. |
| **Look-ahead leakage from start-attributed flow totals in window forecasting** (H7) | L11 (partial flows, per-flow setting); L12 (flow timeouts, title only) | **HYPOTHESIS: possible gap.** L11 supports the premise; L12 must be read. |
| Effect of the CNS2022 corrections on **temporal** task difficulty (H1) | none found | **HYPOTHESIS: possible gap** |
| Temporal evaluation on the **corrected CSE-CIC-IDS2018** | none found (L16–L18 use the corrected 2017 release, per-flow) | **HYPOTHESIS: possible gap**, and the narrowest claim |

**Implication for the framing of the paper** (a recommendation, not a finding):

- **Defensible:** a **measurement study** of how much of the "early warning" skill reported on CIC-derived data survives a leakage-aware evaluation on the corrected releases. That evaluation is persistence-controlled, onset-scored, uses ended flows only, and splits by day in time order.
- **Risky:** a paper that proposes a new forecasting model would compete directly with SENTINEL and the other forecasting work in §5.2.

### 5.3b Gap-targeted searches (round 2, 2026-10-19)

Four extended or standard web searches tested the specific gap candidates:

1. a persistence or naive baseline in network attack forecasting;
2. look-ahead leakage when flows are aggregated into time windows;
3. SENTINEL by name;
4. temporal or early-detection use of the corrected CSE-CIC-IDS2018.

Three follow-up fetches were made: arXiv 2511.23000 (abstract and HTML), the OpenAlex abstracts for 10.3390/app131810411 and 10.3390/electronics15040871, and the MDPI page for app131810411, which returned 403. Six new records, L22–L27, are in `manual_screening.csv`.

| Gap candidate | What round 2 found | Status |
|---|---|---|
| Persistence baseline / onset-only scoring in network-state forecasting | No forecasting work found that reports a persistence baseline. L22 estimates the current attack stage with no external baseline. L23 forecasts window events at 60 s and 120 s, with baselines unknown. L24 shows that filtered-subset scores can hide end-to-end failure. | **HYPOTHESIS: gap holds** at abstract level |
| Look-ahead leakage from start-attributed flow totals | Generic statements only: flow systems see a flow when it ends; time-bin designs assign flows by start time. No measurement found. | **HYPOTHESIS: gap holds** |
| Forecasting or temporal evaluation on the corrected CSE-CIC-IDS2018 | The corrected 2018 release circulates (a Kaggle derivative, L26; a continual-learning repository, L27), but only for per-flow work | **HYPOTHESIS: gap holds** |
| Forecasting as a task | Also ARGUS (L25, unreviewed repository) | Confirms: **not novel as a task** |

SENTINEL could not be found by name in web search beyond its Zenodo record.

### 5.4 Limits of this search (to do before submission)

1. **Full texts not obtained.**
   - L01 SENTINEL: Zenodo returned 403.
   - L03: Preprints.org returned 403.
   - L02 and L07: IEEE paywall.
   - L05: the paper was not located.
   - L12: only the title is indexed.

   Read them before writing the related-work section, by downloading in a browser or through institutional access.
2. **Sources not covered.**
   - Google Scholar, IEEE Xplore, ACM DL and Scopus were not queried directly, because there is no API access. OpenAlex and Semantic Scholar index most of their content, but not all.
   - Backward citations were not traced.
   - Works that use the corrected releases without citing either seed can only be found by the keyword queries.
3. **Single screener.** Screening was done by one reviewer (the assistant) at title and abstract level. A second, human screening of tiers A–C is advisable.
