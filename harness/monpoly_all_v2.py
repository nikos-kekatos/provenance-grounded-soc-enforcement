"""Run the revised MonPoly cross-check (monpoly_check.py, version v2) on the eleven recorded
configurations. Writes ../results/monpoly_v2_<tag>.json and ../results/monpoly_v2_total.json."""
import json, os
from monpoly_check import run
from analyze import RES
TAGS = ["qwen_none", "qwen_def", "qwen_shield", "qwen_forged", "qwen_adaptive", "llama_none", "llama_def",
        "llama_adaptive", "phi4_none", "phi4_def", "phi4_adaptive"]
tot = dict(configs=0, action_calls=0, agree=0, disagree=0, violations_ref=0)
for t in TAGS:
    r = run([os.path.join(RES, f"episodes_{t}.jsonl")], "v2")
    json.dump(r, open(os.path.join(RES, f"monpoly_v2_{t}.json"), "w"), indent=1)
    tot["configs"] += 1
    for k in ("action_calls", "agree", "disagree", "violations_ref"):
        tot[k] += r[k]
    print(t, r["action_calls"], r["agree"], r["disagree"], r["violations_ref"])
print(tot); json.dump(tot, open(os.path.join(RES, "monpoly_v2_total.json"), "w"), indent=1)
