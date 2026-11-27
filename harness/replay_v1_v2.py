"""Replay every recorded action call under the submitted monitors (monitors_v1.py) and the revised
ones (monitors.py, review 2026-10-21). Writes ../results/replay_v1_v2.json with the number of calls
whose violated-property set differs, per monitor, and the agreement of the stateful back-end policy
with the revised trace monitor."""
import glob, json, os
import monitors as m2, monitors_v1 as m1
from analyze import RES
TAGS = ["qwen_none", "qwen_def", "qwen_shield", "qwen_forged", "qwen_adaptive", "llama_none", "llama_def",
        "llama_adaptive", "phi4_none", "phi4_def", "phi4_adaptive"]
import datetime
out = {"rv_vs_percall_permit_refuse_differ": 0, "rv_refuses_percall_permits": [], "p5_calls": [],
       "max_episode_sim_s": 0, "calls": 0, "episodes": 0, "differ": {}, "backend_vs_rv": 0, "backend_vs_percall_db": 0, "examples": []}
for t in TAGS:
    for line in open(os.path.join(RES, f"episodes_{t}.jsonl")):
        ep = json.loads(line)
        if "error" in ep or not ep.get("trace"):
            continue
        out["episodes"] += 1
        tr = ep["trace"]
        dur = (datetime.datetime.fromisoformat(tr[-1]["timestamp"]) - datetime.datetime.fromisoformat(tr[0]["timestamp"])).total_seconds()
        out["max_episode_sim_s"] = max(out["max_episode_sim_s"], dur)
        for i, e in enumerate(tr):
            if e.get("kind") != "call" or not (e["action"] == "act" or e["tool"] == "finish"):
                continue
            if e["action"] == "act":
                out["calls"] += 1
            for name in ("rv", "rv_untyped", "rv_anytool", "rv_untimed", "rv_plus", "percall_db"):
                if e["action"] != "act" and name != "rv_plus":
                    continue
                a, b = sorted(m1.MONITORS[name](tr[:i], e)), sorted(m2.MONITORS[name](tr[:i], e))
                if a != b:
                    out["differ"][name] = out["differ"].get(name, 0) + 1
                    if len(out["examples"]) < 10:
                        out["examples"].append([t, ep["key"], name, e["tool"], e["object"][:40], a, b])
                else:
                    out["differ"].setdefault(name, 0)
            if e["action"] == "act":
                rv2, pc = m2.MONITORS["rv"](tr[:i], e), m2.MONITORS["percall_db"](tr[:i], e)
                if bool(rv2) != bool(pc):
                    out["rv_vs_percall_permit_refuse_differ"] += 1
                    looked = {x["object"] for x in tr[:i] if x.get("kind") == "call" and x["tool"] == "lookup_ioc"}
                    from soc_env import CASE_BY_ID
                    out["rv_refuses_percall_permits"].append([t, ep["key"], e["tool"], e["object"][:40], rv2, pc,
                        CASE_BY_ID[ep["case"]]["ioc"] in looked])
                if "P5" in rv2:
                    out["p5_calls"].append([t, ep["key"], e["tool"], e["object"][:40], rv2])
                bv = sorted(m2.MONITORS["backend"](tr[:i], e))
                out["backend_vs_rv"] += bv != sorted(m2.MONITORS["rv"](tr[:i], e))
                out["backend_vs_percall_db"] += bv != sorted(m2.MONITORS["percall_db"](tr[:i], e))
print(json.dumps(out, indent=1))
json.dump(out, open(os.path.join(RES, "replay_v1_v2.json"), "w"), indent=1)
