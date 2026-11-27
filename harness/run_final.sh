#!/usr/bin/env bash
# Resume 2026-10-20 08:00 after reboot: new adaptive goals (Qwen, Llama) first, then Phi-4. Resumable.
cd "$(dirname "$0")"
python3 run.py --model qwen3.5:9b --tag qwen_adaptive --adaptive --workers 1
python3 run.py --model llama3.2:3b --tag llama_adaptive --adaptive --workers 1
python3 run.py --model phi4:14b --tag phi4_adaptive --adaptive --workers 1
python3 run.py --model phi4:14b --tag phi4_def --defence --workers 1
echo ALLDONE
