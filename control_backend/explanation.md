# control_backend/: the serving backend

## What it does

`control_backend/` is the **FastAPI server** between the models and the K.I.R.A. SOC console (`web_dashboard/`). It:

1. takes live traffic windows from the sensor, or a replayed PCAP or flow file;
2. runs the trained models on each window: TGNE encoder → Branch A → Branch B → DeepOP;
3. turns the outputs into typed events: predictions, forecasts, explanations, topology and campaigns;
4. pushes those events to every open console over a WebSocket;
5. drives the Containerlab cyber range through a small, allowlisted set of commands.

```text
SPAN / PCAP ──► telemetry_service ──► model_adapter (TGNE → A → B → DeepOP) ──► event_broker ──► /ws ──► console
                     │                                                        ▲
                     └► topology_service (live host graph) ───────────────────┘
```

## API (`main.py`)

| Endpoint | Purpose |
|---|---|
| `GET /api/status` | System status: sensor, models, lab |
| `GET /api/scenarios`, `GET /api/site` | Available range scenarios; the active site profile |
| `GET /api/topology` | The current discovered host graph |
| `GET /api/replay/samples`, `POST /api/replay/samples/{name}`, `POST /api/replay` | Offline mode: replay a bundled sample or an uploaded PCAP or flow file through the real sensor and model path |
| `POST /api/command/{cmd_name}`, `POST /api/mitigate` | Allowlisted range commands and mitigations |
| `WS /ws` | The live event stream to the console |

Requests can be protected with an API token (`require_token`).

## Files

| File | Contents |
|---|---|
| `main.py` | The FastAPI app, its endpoints, and PCAP and flow-file replay (grouping records into 2 s windows) |
| `model_adapter.py` | Loads every checkpoint, runs the full inference chain on each window, computes Input × Gradient explanations, and emits a `PredictionEvent` |
| `telemetry_service.py` | Starts live SPAN capture (`scripts/run_telemetry.sh`) and feeds windows to the model adapter |
| `topology_service.py` | Builds the live host graph from observed flows (internal or external by site CIDRs), with TTL eviction and a node cap |
| `event_broker.py` | Asynchronous WebSocket broadcast to all dashboards, without blocking capture or inference |
| `schema.py` | Pydantic models for every event (prediction, forecast point, explanation, topology, status, command, attack). They keep the console independent of model internals. |
| `correlation_service.py` | Feeds observed and forecast attack steps into `correlation/` to assemble multi-host campaigns. This is a heuristic, and labelled as one. |
| `forecast_branches.py` | DeepOP's three most likely continuations, for the console's forecast tree |
| `forecast_band.py` | The uncertainty band for each forecast step, from the Branch B checkpoint's conformal fit. No fitted band means no band. |
| `tactics.py` | Maps Branch A techniques and DeepOP tokens onto one kill-chain strip, and marks the lanes the models cannot yet predict |
| `evidence.py` | The flows and the 27-dimensional state behind a verdict, as the console lists them |
| `capture_accounting.py` | Detects windows that were dropped or captured incompletely, so a flood that overloads the sensor is not mistaken for quiet traffic |
| `commands.py` | Allowlisted executor for the Containerlab range. Attacks are external, never simulated flows. |
| `site_config.py`, `lab_config.py` | Site profiles (CIDRs, sensor, assets of interest) from `config/sites/*.yaml`, and paths into the range |

## How it is run

```bash
python run_dashboard.py          # backend + console, live
python run_dashboard.py --demo   # offline demo
```

Select a site with `CYBERWORLD_SITE` or `CYBERWORLD_SITE_CONFIG`.
