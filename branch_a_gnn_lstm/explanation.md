# branch_a_gnn_lstm/: Branch A, "what is happening now"

## What it does

Branch A reads the recent history of one host and answers three questions about that host's **current** state:

1. **Risk:** how likely is it that this host is under attack (a score from 0 to 1)?
2. **Technique:** which MITRE ATT&CK technique best matches the activity (for example `T1046` network scanning, or `Benign`)?
3. **Gradation:** how severe or advanced is the attack?

It follows the GNN-LSTM method of Vitulyova et al., *A Hybrid Approach Using Graph Neural Networks and LSTM for Attack Vector Reconstruction* (Computers 14(8):301, 2025).

## Where it sits

```text
bita/ (TGNE encoder) ──► host state per window ──► Branch A ──► risk, technique, stage
                                                   Branch B ──► future states (see branch_b_world_model/)
```

## Input and model

- **Input per host:** a sequence of the last 15 windows of 2 s each (30 s of history). Each step is a 27-dimensional vector: the 12-D host embedding from the TGNE encoder plus 15 host attributes (rates, counts, timing and similar).
- **Model:** an LSTM over the sequence, with three output heads:
  - risk: sigmoid;
  - technique: softmax over the technique vocabulary;
  - gradation.
- **Loss:** 0.5 × risk loss (BCE) + 0.3 × technique loss (cross-entropy) + 0.2 × gradation loss (MSE), as in the paper.
- **Kept deviations from the paper** (documented in `lstm_multitask.py`):
  - The technique loss is class-weighted, because about 82.5% of the training sequences are benign. The paper used SMOTE, which does not apply to overlapping sequences.
  - Older checkpoints with a 2 × 64 LSTM and attention readout can still be loaded.

## Logistic-regression benchmark

The problem statement asks for a comparison against logistic regression on the same features. `logistic_baseline.py` provides it with:

- the **same** 27 × 15 input tensor (flattened), the **same** binary target, and the **same** rule for picking the decision threshold on validation;
- a streaming fit, because the training split is about 20.7 million windows (about 33 GB), too large for scikit-learn in memory.

## Files

| File | Contents |
|---|---|
| `lstm_multitask.py` | `MultiTaskLSTM` (the model), focal loss, multi-task loss weighting |
| `attention.py` | Temporal self-attention over LSTM hidden states (used by the legacy architecture) |
| `sequence_dataset.py` | Builds per-host sliding-window samples and targets, in memory or lazily (`LazyHostSequenceDataset`) for large corpora |
| `train_branch_a.py` | Standalone trainer. Loads the TGNE encoder (`build_or_load_tgne_ta`), builds sequences, trains, and saves the best epoch by validation loss. |
| `logistic_baseline.py` | The logistic-regression benchmark described above |

## How it is run

The full plan (`./train.sh`) trains Branch A after the encoder, together with the logistic baseline, through `scripts/retrain_branch_a_live.py`. To train it on its own:

```bash
python branch_a_gnn_lstm/train_branch_a.py
```

At serving time, `control_backend/model_adapter.py` runs Branch A on every live window. The console shows its risk, technique and kill-chain stage, and Input × Gradient attributions over the 27 input dimensions.
