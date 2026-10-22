# deepop_decoder/: DeepOP, "which attack stages come next"

## What it does

DeepOP is the last model in the pipeline. It turns the two branches' outputs into a forecast of the **next MITRE ATT&CK stages** for a host. For example: reconnaissance now, then initial access, then command-and-control.

```text
bita/ (TGNE) ──► Branch A: technique per window (what is happening now)  ──┐
             └─► Branch B: predicted future host states (what happens next) ┴─► DeepOP ──► next ATT&CK tokens
                                                                                      ──► control_backend/ (forecast tree, kill chain)
```

It follows Zhang, Xue and Su, *DeepOP: A Hybrid Framework for MITRE ATT&CK Sequence Prediction via Deep Learning and Ontology* (Electronics 14(2):257, 2025, Section 3.4).

## Model

DeepOP is an **encoder–decoder Transformer** over ATT&CK tokens.

1. **Encoder** (paper Eqs. 1–6):
   - **Input:** the host's observed technique sequence, which is Branch A's technique for each of the last 15 windows.
   - **Processing:** the tokens are embedded, sinusoidal positional encodings are added, and the sequence passes through temporal multi-head attention layers.
2. **Decoder** (Eqs. 7–10):
   - **Generation:** it produces the next tokens one at a time, autoregressively.
   - **Attention:** it uses **causal window attention** (`cwa.py`). The heads are split into groups, by default 6 heads in 3 groups. Each group partitions the sequence into windows of its own size and attends causally inside each window, so the model sees short- and longer-range patterns at once.
   - **Cross-attention:** it attends both to the encoder output **and** to Branch B's predicted future host states. Both branches therefore reach DeepOP as learned inputs.
3. **Loss** (Eq. 11): cross-entropy over the token vocabulary.

## Departures from the paper

Both are forced by the data, and both are documented in `forecast_decoder.py`:

- **Embeddings are learned instead of Word2Vec.** The vocabulary has only about 10 tokens, too few for skip-gram to add anything.
- **The decoder also attends to Branch B's continuous future states.** The paper works on text-derived threat-intelligence sequences and has no equivalent input.

## Vocabulary (`joint_vocab.py`)

Fine-grained dataset labels from CIC, CTU-13 and Warden are consolidated into joint `Category.Technique` tokens. There are 7 tokens plus the special tokens `<PAD>`, `<BOS>` and `<EOS>`:

| Category | Technique |
|---|---|
| Benign | — |
| Recon | T1595 |
| InitialAccess | T1190 |
| CredentialAccess | T1110 |
| C2 | T1071 |
| Exfiltration | T1005 |
| Impact | T1498 |

The console uses the same consolidation (`control_backend/tactics.py`), so the kill-chain strip and the model cannot drift apart. There are no Execution or Lateral Movement tokens: these cannot be observed from network flows alone, so the console marks those lanes as under development.

## Honest evaluation

`DeepOPTokenScorer` and `evaluate_forecast_rigor` score the decoder against baselines that get **the same information**.

The problem they fix: an earlier validation gave the model the true previous token at every step (teacher forcing), while the "persistence" baseline had to hold one token for the whole horizon. That made the model look better than it was.

Now the decoder runs in free-running mode and is compared with free-running baselines, so a gain over "keep predicting the current stage" is real.

## Files

| File | Contents |
|---|---|
| `forecast_decoder.py` | `DeepOPForecastDecoder` (encoder, CWA decoder layers, greedy `forecast_sequence`), positional encoding, the token scorer and the matched-baseline evaluation |
| `cwa.py` | `CausalWindowAttention`: partitioned windows as in the paper; a sliding variant is kept for older checkpoints |
| `joint_vocab.py` | The joint token vocabulary and the label consolidation |
| `train_cwa_decoder.py` | Builds training samples (observed tokens, Branch B future states, target tokens), in memory or lazily from a trajectory store. Trains and saves to `saved_models/deepop/cwa_forecast_decoder.pt`. |

## How it is run

- **In `./train.sh`:** DeepOP is trained last, and **only if Branch B beats the copy-the-last-state baseline**. Without a useful world model there is nothing to condition on.
- **On its own:** call `train_cwa_decoder(...)` in `train_cwa_decoder.py`.
- **At serving time:** `control_backend/model_adapter.py` runs the greedy forecast for each window, and `control_backend/forecast_branches.py` decodes the three most likely alternative continuations for the console's forecast tree.
