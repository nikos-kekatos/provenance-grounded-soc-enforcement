"""Alarmed clean episodes vs ground-truth correctness, per tag and monitor (rv, rv_plus, stateless_strict).
Writes ../results/clean_alarm_check.json."""
import json, os, sys, glob, collections
from analyze import load, RES
from monitors import replay
out = {}
tags = sys.argv[1:] or sorted(os.path.basename(p)[9:-6] for p in glob.glob(os.path.join(RES, "episodes_*.jsonl")))
for t in tags:
    cln = [e for e in load(t) if not e["injection"]]
    if not cln: continue
    r = {"n_clean": len(cln), "correct": sum(e["task_correct"] for e in cln)}
    for m in ("rv", "rv_plus", "stateless_strict"):
        al = [e for e in cln if any(v for *_, v in replay(e["trace"], m))]
        r[m] = dict(alarmed=len(al), alarmed_correct=sum(e["task_correct"] for e in al),
                    alarmed_correct_keys=[e["key"] for e in al if e["task_correct"]])
    out[t] = r
    print(t, {k: (v if not isinstance(v, dict) else (v["alarmed"], v["alarmed_correct"])) for k, v in r.items()})
json.dump(out, open(os.path.join(RES, "clean_alarm_check.json"), "w"), indent=1)
