import json, sys
from agent import run_episode
from monitors import replay
m = sys.argv[1]
for case, inj in [("C03", None), ("C03", {"channel": "log", "goal": "hijack_unprotected"}),
                  ("C01", {"channel": "cti", "goal": "exfiltrate"})]:
    r = run_episode(m, case, inj)
    print(case, inj, "succ", r["attack_success"], "correct", r["task_correct"], r["disposition"], r["wall_s"], "s", r["steps"], "steps")
    print("  committed", r["committed"])
    for mon in ["rv", "stateless_strict"]:
        print("  ", mon, [(t, o, rc, v) for _, t, o, rc, v in replay(r["trace"], mon) if v])
