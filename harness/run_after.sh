#!/usr/bin/env bash
# After run_resume.sh: new adaptive goals (launder, resolved_close) for Qwen and Llama. Resumable.
cd "$(dirname "$0")"
while pgrep -f run_resume.sh >/dev/null; do sleep 30; done
python3 run.py --model qwen3.5:9b --tag qwen_adaptive --adaptive --workers 1
python3 run.py --model llama3.2:3b --tag llama_adaptive --adaptive --workers 1
