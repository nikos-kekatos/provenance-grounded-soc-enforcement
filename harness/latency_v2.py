"""Revised monitors (review 2026-10-21); writes latency_v2.json, leaving latency.json (submitted monitors) intact."""
"""Per-call verdict latency of the Python reference monitor (rv), replayed on recorded traces.
Writes ../results/latency.json. Each action call is judged on its own prefix, as in a shield."""
import json, os, statistics, sys, time, platform
from analyze import load, RES
from monitors import MONITORS
tags = sys.argv[1:] or ["qwen_none", "qwen_def", "llama_none", "llama_def"]
ts, plen = [], []
for t in tags:
    for e in load(t):
        tr = e["trace"]
        for i, x in enumerate(tr):
            if x.get("kind") == "call" and x.get("action") == "act":
                t0 = time.perf_counter(); MONITORS["rv"](tr[:i], x); ts.append(time.perf_counter() - t0); plen.append(i)
ts.sort()
r = dict(tags=tags, calls=len(ts), median_us=round(1e6 * statistics.median(ts), 1),
         p99_us=round(1e6 * ts[int(0.99 * len(ts))], 1), max_us=round(1e6 * ts[-1], 1),
         max_prefix_events=max(plen), machine=platform.platform() + " " + platform.machine(), python=platform.python_version())
llm = [e["wall_s"] for t in tags for e in load(t)]
r["episode_wall_s_median"] = round(statistics.median(llm), 1)
print(r); json.dump(r, open(os.path.join(RES, "latency_v2.json"), "w"), indent=1)
