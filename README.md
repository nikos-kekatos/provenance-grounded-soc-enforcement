# Provenance-Grounded Runtime Enforcement for Agentic SOC Assistants

Simulation environment, attack payloads, monitors, recorded traces and analysis scripts for the paper

> G. Koutidis, N. Kekatos, T. Nestoridis, A. Lekidis, P. Katsaros and T. Nianios,
> "Provenance-Grounded Runtime Enforcement for Agentic SOC Assistants under Prompt Injection,"
> CyberHunt 2026 (IEEE BigData 2026 workshops).

A language-model SOC assistant triages twelve simulated cases. An attacker injects instructions through an
alert field, a log message or a threat-intelligence report. A runtime monitor checks every proposed response
action against five past-time MFOTL obligations (P1 to P5) over the tool trace, before the action executes.

## Contents

| Path | What it is |
|---|---|
| `harness/soc_env.py` | SOC environment: 12 cases, tools, field trust domains, call-answer binding, injection payloads (`attack_payload`) |
| `harness/agent.py` | JSON-action agent over Ollama (system prompt with the runbook, prompt-level defence) |
| `harness/monitors.py` | Reference monitor P1 to P5 (and P4c, P6), deny-lists, per-call and stateful back-end policies, ablations |
| `harness/monitors_v1.py` | The monitor with once-record semantics (used for the replay comparison) |
| `harness/run.py`, `harness/run_*.sh` | Episode runner and the sweep drivers |
| `harness/analyze.py`, `make_tables.py`, `goal_breakdown.py`, `review_stats.py`, `redteam_checks.py` | Attack success, detection, clean alarms, paired statistics, tables |
| `harness/monpoly_check.py`, `monpoly_all_v2.py` | Export to MonPoly log format and cross-check with the unmodified MonPoly (Docker image `infsec/monpoly`) |
| `harness/temporal_suite.py` | Scripted traces with changing records (36 decisions) and P5 boundary traces (32 decisions) |
| `harness/test_extractor.py` | 19 hand-written extractor tests |
| `harness/live_ext.py` | Live verdict-retraction runs |
| `harness/latency_v2.py` | Monitor timing |
| `harness/orig_labels_full.py` | Figures recomputed under the original C02/C10 labels |
| `results/episodes_<model>_<config>.jsonl` | Every recorded episode with its full tool trace (1,602 episodes) |
| `results/summary.json` | Attack success, detection and clean alarms per configuration |
| `results/monpoly_*.json` | MonPoly verdicts per configuration |
| `results/live_*_retract.jsonl`, `live_ext_summary.*` | Live retraction runs |
| `results/temporal_suite.json`, `extractor_tests.json`, `replay_v1_v2.json`, `latency_v2.json`, `review_stats.json`, `redteam_checks.json`, `goal_breakdown.json`, `clean_alarm_check.json` | The sources of the remaining figures in the paper |

Configuration tags: `qwen` = qwen3.5:9b, `phi4` = phi4:14b, `llama` = llama3.2:3b; `none` = undefended,
`def` = prompt-level defence, `shield` = monitor in the loop, `forged` = forged-structure injection,
`adaptive` = the four goals that target the obligations.

## Requirements

- Python 3.10 or later; the harness uses only the standard library.
- Ollama with the three models (Q4_K_M), for new runs. The recorded traces need no model.
- Docker with `infsec/monpoly`, for the MonPoly cross-check.

## Reproducing the figures from the recorded traces

```sh
cd harness
python3 analyze.py            # results/summary.json
python3 make_tables.py        # Tables of attack success and detection
python3 review_stats.py       # paired defence statistics, competent cases
python3 redteam_checks.py     # strict correctness, original labels, case bootstrap
python3 goal_breakdown.py     # adaptive goals
python3 temporal_suite.py     # scripted changing-record traces
python3 test_extractor.py     # extractor tests
python3 monpoly_all_v2.py     # MonPoly cross-check (Docker)
```

## New runs

```sh
cd harness
python3 run.py --model qwen3.5:9b --tag qwen_none --workers 1
python3 run.py --model qwen3.5:9b --tag qwen_def --defence --workers 1
python3 run.py --model qwen3.5:9b --tag qwen_adaptive --adaptive --workers 1
python3 live_ext.py run --model qwen3.5:9b --tag qwen_retract --exp retract --reps 5
```

Seeds are derived from the episode key, so reruns with the same model build give the same episodes up to the
non-determinism of the model server.

## AI assistance

Anthropic's Claude assisted with the automation of the experiments and the editing of the manuscript.
