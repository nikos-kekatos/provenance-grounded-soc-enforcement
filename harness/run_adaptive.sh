#!/usr/bin/env bash
# Adaptive attacks (exfil to trusted contact, omission), after run_all.sh. Resumable.
cd "$(dirname "$0")"
python3 run.py --model qwen3.5:9b --tag qwen_adaptive --adaptive --workers 1
python3 run.py --model phi4:14b --tag phi4_adaptive --adaptive --workers 1
python3 run.py --model llama3.2:3b --tag llama_adaptive --adaptive --workers 1
