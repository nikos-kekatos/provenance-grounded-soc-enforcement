#!/usr/bin/env bash
# Live extension runs (2026-10-27): retraction on three models, obfuscated leak on Qwen. Resumable.
cd "$(dirname "$0")"
python3 live_ext.py run --model qwen3.5:9b --tag qwen_retract --exp retract --reps 5
python3 live_ext.py run --model qwen3.5:9b --tag qwen_obf --exp obf
python3 live_ext.py run --model phi4:14b --tag phi4_retract --exp retract --reps 5
python3 live_ext.py run --model llama3.2:3b --tag llama_retract --exp retract --reps 5
python3 live_ext.py analyze
