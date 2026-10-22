# bita/: the TGNE encoder

## What it does

`bita/` turns network traffic into a learned state for every host. It is the first model in the K.I.R.A. pipeline, and the other models build on what it produces:

```text
telemetry/ (flows, 2 s windows) ──► bita/ (TGNE encoder) ──► Branch A, Branch B ──► DeepOP ──► control_backend/
```

Each 2-second window of traffic is treated as an interaction graph:

- **Nodes** are hosts.
- **Edges** are flows, each with 12 features: forward and backward bytes and packets (log-scaled), duration, byte and packet rates, TCP/UDP/ICMP flags, the normalised destination port, and direction asymmetry.

The encoder is a **Temporal Graph Network (TGN)** (Rossi et al., 2020). Every host keeps a memory vector that is updated whenever it takes part in a flow. A graph-attention layer combines a host's memory with its recent neighbours to produce an embedding.

The **BiTA** change (Makki Nayeri and Rezvani) is in how a host's waiting messages are merged before its memory updates. Plain TGN keeps the last message or the mean; BiTA runs a bidirectional GRU followed by a Transformer encoder over the message sequence (`aggregator_type: "bigru_transformer"`).

The model is trained self-supervised, on two tasks:

1. **Link prediction:** will this host pair interact?
2. **Edge-category prediction:** which class does the flow belong to (81 categories in the served config)? Focal loss handles the class imbalance.

## What it gives the rest of the system

`model/extentedtgn.py` (`ExtendedTGN`) adds two outputs to the standard TGN:

- **`get_host_embeddings(node_ids, timestamp)`:** the 12-dimensional latent state *H<sub>t</sub>*[*v*] of each host. Branch A and Branch B read this, concatenated with 15 host attributes.
- **`get_global_state(H_t)`:** a pooled, network-wide state.

## Layout

| Path | Contents |
|---|---|
| `train.py` | Main training entry point: data loading (CIC, CTU-13, unified records), splits, the training loop with TrainingGuard (warm-up, clipping, roll-back, early stopping), checkpointing |
| `model/tgn.py`, `model/extentedtgn.py` | TGN core and the extended model with category head and host-state extraction |
| `model/temporal_attention.py`, `model/time_encoding.py` | Multi-head temporal attention; time encoding of event gaps |
| `modules/` | TGN building blocks: memory, memory updater (GRU/RNN), message function, message aggregator (last, mean, **BiTA**), embedding module (graph attention and others) |
| `fast/` | Opt-in fast training step (`--fast_step`). It computes the same function with fewer Python loops and device syncs, and adds a batch planner, CUDA graphs and a Triton BiGRU kernel. `fast/bench.py` checks numerical equivalence with the reference step. |
| `utils/` | Neighbour finder, negative sampler, early stopping, disk-backed store; `setup_store.py` shares one prepared data setup across runs; `tgn_host.py` bridges to the Rust hot loops in `rust/tgn_host` |
| `evaluation/eval_edge_prediction_with_categories.py` | Link and category evaluation |
| `* stage/` folders | The original BiTA pipeline split into stages (loading, bipartite graph, features, time statistics, splitting, self-supervised training), kept for reference |
| `saved_models/` | The served checkpoint (`bita_bigru_transformer-warden_alerts.pth`) and its config (`bita_config.json`: 1 layer, 2 heads, 12-D memory, BiTA aggregator, the 12 edge-feature names) |

## How it is run

`./train.sh` trains the encoder first: with and without IP-identity features, over three seeds. To train it on its own:

```bash
python bita/train.py --use_memory --n_degree 10 ...   # see the argparse options in train.py
```

At serving time, `control_backend/model_adapter.py` loads the checkpoint in `saved_models/` and runs the encoder on each live window.
