#!/usr/bin/env bash
# Rerun 2026-10-20 after the 08:16 Ollama shutdown: phi4_def and phi4_adaptive only.
# Headless ollama serve, restarted by a watchdog if it dies. Run under caffeinate -dimsu.
cd "$(dirname "$0")"
serve() { nohup env OLLAMA_MAX_LOADED_MODELS=1 OLLAMA_KEEP_ALIVE=-1 ollama serve \
            >> ~/.ollama/logs/serve-cli.log 2>&1 & }
up() { curl -s -m 10 localhost:11434/api/version > /dev/null; }
( while true; do up || { echo "$(date) watchdog: restarting ollama serve"; serve; }; sleep 60; done ) &
WD=$!
trap 'kill $WD' EXIT
for pass in 1 2; do                            # pass 2 picks up episodes that still failed
  python3 run.py --model phi4:14b --tag phi4_def --defence --workers 1
  python3 run.py --model phi4:14b --tag phi4_adaptive --adaptive --workers 1
done
echo ALLDONE
