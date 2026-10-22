# branch_b_world_model/: Branch B, "what happens next"

## What it does

Branch B is a **world model** for each host. Given the recent history of a host's state, it predicts how that state will evolve over the next few steps. Then it estimates the probability that the host will be compromised along the way.

Branch A says what is happening now. Branch B forecasts what is likely to happen next. It learns *P*(*s*(*t*+1 … *t*+5) | *s*(*t*−14 … *t*)).

## Where it sits

```text
bita/ (TGNE encoder) ──► host state H_t[v] ──► Branch B ──► predicted states H_{t+1..t+5}[v] + uncertainty
                                                         └► infiltration risk per step and over the horizon
                                                             ──► DeepOP decoder (next ATT&CK stages)
```

## Model

**`HostWorldDynamicsTransformer`** (`rollout_encoder_decoder.py`) is a causal Transformer that rolls a host's latent state forward one step at a time:

- **Inputs:** the last 15 host states of 2 s each (30 s of history).
- **Forecast:** 5 steps of 30 s each, or 150 s ahead. Each future step aggregates 15 input windows, and a step is an attack if any window in it is one. The step sizes are set in `cyberworld_v4/config.py`.
- **Residual prediction:** the model predicts the change, *H*<sub>*t*+*k*</sub> = *H*<sub>*t*+*k*−1</sub> + Δ*H*, rather than the raw state.
- **Uncertainty:** it outputs a Gaussian (mean and variance) for each predicted step, trained with Gaussian negative log-likelihood.
- **Time encoding:** elapsed time is encoded continuously, so steps of different lengths can be told apart.
- **Fast rollout:** causal attention with a key–value cache.
- **Host interactions:** an optional layer lets hosts that interact influence each other's forecasts.

**`InfiltrationRiskHead`** (`infiltration_head.py`) is a small MLP that maps each predicted state to a compromise probability *r*<sub>*t*+*k*</sub>. It combines them into a cumulative horizon risk *R* = 1 − ∏(1 − *r*<sub>*t*+*k*</sub>).

## Files

| File | Contents |
|---|---|
| `rollout_encoder_decoder.py` | The world-dynamics Transformer, time encoding, cross-host interaction layer, Gaussian NLL |
| `infiltration_head.py` | Per-step and cumulative risk head |
| `train_branch_b.py` | Builds (history, future, risk) samples from host trajectories, in memory or lazily from a trajectory store. Trains with a discounted multi-horizon loss (γ = 0.9). Saves the best epoch with its temporal-contract fields, so serving can reject a checkpoint built for different window settings. |

## The rule it must pass

A forecast is only useful if it beats simply **copying the last state**. In `./train.sh`, Branch B is followed by DeepOP **only if** it beats that copy-the-last-state baseline.

## How it is run

`./train.sh` trains it after Branch A. On its own, call `train_branch_b(...)` in `train_branch_b.py`, as the scripts in `scripts/` do.

At serving time, `control_backend/model_adapter.py` produces the rollout for each window. The console draws the risk timeline and forecast. The uncertainty band comes from the checkpoint's conformal calibration (`control_backend/forecast_band.py`), and no band is drawn when the checkpoint has none.
