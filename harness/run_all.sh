#!/usr/bin/env bash
# Full sweep, sequential by model so Ollama keeps one model resident. Resumable.
set -u
cd "$(dirname "$0")"
Q=qwen3.5:9b; P=phi4:14b; L=llama3.2:3b
python3 run.py --model $Q --tag qwen_none --workers 1
python3 run.py --model $Q --tag qwen_def --defence --workers 1
python3 run.py --model $Q --tag qwen_shield --shield rv --workers 1
python3 run.py --model $Q --tag qwen_forged --variant forged --no-clean --workers 1
python3 run.py --model $L --tag llama_none --workers 1
python3 run.py --model $L --tag llama_def --defence --workers 1
python3 run.py --model $P --tag phi4_none  --workers 1
python3 run.py --model $P --tag phi4_def --defence  --workers 1
