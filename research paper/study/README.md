# Study folder

Papers for the study guide given in chat on 2026-10-19. The folders follow its steps (01 = Step 1, and so on). There is no `03_…` folder: Step 3, data-auditing skills, is learnt from tool documentation and from `src/audit/self_review.py`, not from papers.

- **Downloaded by:** `python -I src/lit/fetch_study_papers.py`.
- **Sources:** open copies only — arXiv, open-access publishers, the RFC Editor, and author or university repositories.
- **Log:** every source URL, SHA-256 and the result of each attempt is in `download_log.csv`.
- **For personal study only.** Do not redistribute. `.gitignore` keeps the PDFs out of any repository.

## What to print first (about 74 pages)

| # | File | Pages | Why |
|---|---|---:|---|
| 1 | `02_datasets_and_their_errors/Liu2022_Error_Prevalence_CNS2022.pdf` | 10 | **The** paper behind the data you use. Read all of it. |
| 2 | `02_datasets_and_their_errors/Engelen2021_Troubleshooting_CICIDS2017_SPW.pdf` | 6 | Where the flow-construction errors (FIN/RST, "TCP appendix" flows) were first shown |
| 3 | `02_datasets_and_their_errors/Sharafaldin2018_CICIDS2017_ICISSP.pdf` | 9 | How CIC-IDS2017 was generated, and its attack schedule |
| 4 | `04_leakage_and_evaluation/Arp2022_Dos_and_Donts_ML_Security_USENIX.pdf` | 18 | The 10 pitfalls (data snooping, spurious correlations, …). Our protocol rests on this paper. |
| 5 | `07_forecasting_literature_and_gap/Moczkodan2026_Transformers_Temporal_CICIDS2017_arXiv.pdf` | 11 | The closest temporal evaluation on CIC-IDS2017 that we could read in full (original release, current-flow labels) |
| 6 | `02_datasets_and_their_errors/Flood_PhD_thesis_…pdf`, **pages 52–71 only** (Chapter 3) | 20 | "Bad data design smells" in NIDS benchmarks |

## Everything in the folder

Priority: **must** = print and read closely; **should** = read; **ref** = consult when needed.

| Step | File | Pages | Priority | Focus on |
|---|---|---:|---|---|
| 1 Networking and flows | `01_networking_and_flows/RFC7011_IPFIX_2013.txt` | text | ref | §1–3 only (terminology, what a flow record is) |
| 2 Datasets and errors | `…/Liu2022_Error_Prevalence_CNS2022.pdf` | 10 | must | all; Tables I–V; §IV-B on the CICFlowMeter fixes |
| 2 | `…/Engelen2021_Troubleshooting_CICIDS2017_SPW.pdf` | 6 | must | the flow-construction and labelling problems |
| 2 | `…/Sharafaldin2018_CICIDS2017_ICISSP.pdf` | 9 | must | attack schedule, testbed, feature list |
| 2 | `…/Rosay2022_LycoS_CICIDS2017_ICISSP.pdf` | 12 | should | the other corrected version (LycoS); why "improved CIC-IDS2017" is ambiguous |
| 2 | `…/Flood_PhD_thesis_Edinburgh_incl_Bad_Design_Smells.pdf` | 205 | must / ref | **pp. 52–71** (Chapter 3, the EuroS&P 2024 paper); pp. 72–97 (Chapter 4) optional |
| 4 Leakage and evaluation | `04_…/Arp2022_Dos_and_Donts_ML_Security_USENIX.pdf` | 18 | must | §2, the pitfalls; data snooping and temporal snooping |
| 4 | `04_…/Geirhos2020_Shortcut_Learning.pdf` | 29 | should | §1–3 (what a shortcut is and how to detect it); skip the vision examples |
| 4 | `04_…/Cantone2024_Cross_Dataset_Generalization_NIDS.pdf` | 23 | should | cross-dataset results among CIC-IDS2017, CSE-CIC-IDS2018 and LycoS (our H3) |
| 6 Metrics | `06_…/Saito2015_Precision_Recall_Imbalanced_PLOSONE.pdf` | 21 | should | why PR curves rather than ROC when attacks are rare |
| 7 Forecasting and the gap | `07_…/Moczkodan2026_Transformers_Temporal_CICIDS2017_arXiv.pdf` | 11 | must | split definitions, padding effect, the "time-based split is degenerate" remark |
| 7 | `07_…/Ahmed2024_Rapid_Forecasting_Cyber_Events_Information.pdf` | 16 | should | forecasting on CSE-CIC-IDS2018 (original release). Check their baseline and split. |
| 7 | `07_…/Survey2026_Contextualized_NetFlow_NIDS_arXiv.pdf` (El Mahdaouy et al.) | 21 | should | the section on evaluation failure modes (temporal leakage, splitting) |
| 7 | `07_…/Youssef2026_Stream_Assembly_Streaming_IDS_arXiv.pdf` | 24 | should | how the order in which a stream is assembled changes results (why we never cross days) |
| 7 | `07_…/Wang2025_Modular_Intrusion_Predictors_arXiv.pdf` | 9 | ref | stage prediction from alert windows (current stage, not future) |
| 8 Research method | `08_…/Kitchenham2007_SLR_Guidelines_EBSE.pdf` | 65 | ref | §5–6 (planning and conducting a review) |

## Not downloaded: get these yourself

**Free, but the site refused automated download.** Open these in a browser and save or print them:

| Paper | Link | Step |
|---|---|---|
| Hyndman & Athanasopoulos, *Forecasting: Principles and Practice* (3rd ed.), §5.2 "Some simple forecasting methods" and §5.10 "Time series cross-validation" | https://otexts.com/fpp3/simple-methods.html · https://otexts.com/fpp3/tscv.html | 5 (**must**) |
| Axelsson 2000, *The Base-Rate Fallacy and the Difficulty of Intrusion Detection* (ACM open backfile) | https://dl.acm.org/doi/10.1145/357830.357849 | 6 (**must**, 20 pp.) |
| Lanvin et al. 2022, *Errors in the CICIDS2017 Dataset…* (HAL) | https://hal.science/hal-03775466 | 2 |
| Ji, Jeong, Jeong 2023, *Temporal Features … to Forecast Network Events* (MDPI, open access) | https://www.mdpi.com/2076-3417/13/18/10411 | 7 |
| Page et al. 2021, *The PRISMA 2020 statement* (BMJ, open access) | https://www.bmj.com/content/372/bmj.n71 | 8 |
| **SENTINEL** (Shahane et al., 2026 preprint): the closest prior work | https://zenodo.org/records/22212693 | 7 (**must**) |
| *The Evaluation Protocol Is the Hidden Variable* (2026 preprint) | https://www.preprints.org/manuscript/202606.0903/v1 | 7 |

**Paywalled.** Use your university library or an author copy:

| Paper | Where | Step |
|---|---|---|
| Kaufman, Rosset, Perlich, Stitelman 2012, *Leakage in Data Mining* (ACM TKDD) | https://doi.org/10.1145/2382577.2382579 | 4 (**must**) |
| D'hooge et al. 2022, *Contaminating Effect of Metadata Feature Inclusion…* (DIMVA, Springer LNCS 13358) | https://imec-publications.be/handle/20.500.12860/40718 | 4 |
| Husák et al. 2019, *Survey of Attack Projection, Prediction, and Forecasting in Cyber Security* (IEEE COMST) | https://doi.org/10.1109/COMST.2018.2871866 | 7 (**must**) |
| Flood et al. 2024, *Bad Design Smells in Benchmark NIDS Datasets* (IEEE EuroS&P) | https://ieeexplore.ieee.org/document/10629000. Its content is Chapter 3 of the thesis above. | 2 |
| Drift-robust evaluation on CSE-CIC-IDS2018 (IEEE ICDSCA 2025) | https://doi.org/10.1109/icdsca67083.2025.11349773 | 7 |
| Hybrid DL framework for proactive intrusion detection (IEEE CICN 2025) | https://doi.org/10.1109/cicn67655.2025.11367850 | 7 |
| Early-stage anomaly detection: complete vs partial flows (IEEE EuroS&PW 2025) | https://doi.org/10.1109/eurospw67616.2025.00024 | 7 |
| IDS2Eval paper (2026); only its artifacts were found | https://doi.org/10.5281/zenodo.23301257 | 7 |

**Books** (library):

| Book | Read | Step |
|---|---|---|
| Kurose & Ross, *Computer Networking: A Top-Down Approach* | transport-layer chapter (TCP connection management) | 1 |
| López de Prado, *Advances in Financial Machine Learning* | the cross-validation chapter on purging and embargo | 4 |
| Efron & Tibshirani, *An Introduction to the Bootstrap* | first chapters | 5 |

## Printing tips

- **Duplex, 2 pages per sheet,** works for the arXiv and SciTePress papers. Print the CNS2022 paper at full size: its tables are dense.
- **For the thesis,** print only pages 52–71 (set the page range in the print dialog).
- **The RFC is plain text.** Print §1–3 from a text editor or browser.
