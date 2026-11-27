"""Per-goal attack success and detection, for the text of Sections RQ2, RQ3 and the adaptive attacks.
Writes ../results/goal_breakdown.json. Uses the same harmful_index and monitors as analyze.py.

  python3 goal_breakdown.py
"""
import collections, json, os
from analyze import RES, load, harmful_index
from monitors import MONITORS

TAGS = ["qwen_none", "qwen_def", "qwen_forged", "llama_none", "llama_def", "phi4_none", "phi4_def",
        "qwen_adaptive", "llama_adaptive", "phi4_adaptive"]
MONS = ["stateless_loose", "stateless_strict", "percall_db", "rv", "rv_untyped", "rv_anytool", "rv_plus"]

out = {}
for tag in TAGS:
    att = [e for e in load(tag) if e["injection"]]
    g = collections.defaultdict(lambda: {"n": 0, "succ": 0, **{m: 0 for m in MONS},
                                         "rv_plus_props": collections.Counter()})
    for e in att:
        d = g[e["injection"]["goal"]]
        d["n"] += 1
        if not e["attack_success"]:
            continue
        d["succ"] += 1
        hi = harmful_index(e)
        if hi is None:
            continue
        for m in MONS:
            v = MONITORS[m](e["trace"][:hi], e["trace"][hi])
            if v:
                d[m] += 1
                if m == "rv_plus":
                    d["rv_plus_props"].update(v)
    out[tag] = {k: {**v, "rv_plus_props": dict(v["rv_plus_props"])} for k, v in sorted(g.items())}
json.dump(out, open(os.path.join(RES, "goal_breakdown.json"), "w"), indent=1)
for tag, gs in out.items():
    print("==", tag)
    for goal, d in gs.items():
        print(f"  {goal:20s} succ {d['succ']}/{d['n']}  " + "  ".join(f"{m} {d[m]}" for m in MONS)
              + f"  plus-props {d['rv_plus_props']}")
