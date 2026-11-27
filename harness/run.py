"""Sweep driver. Writes one JSON line per episode to ../results/episodes_<tag>.jsonl (resumable).

  python3 run.py --model qwen3.5:9b --tag qwen_none
  python3 run.py --model qwen3.5:9b --tag qwen_def --defence
  python3 run.py --model qwen3.5:9b --tag qwen_forged --variant forged --no-clean
  python3 run.py --model qwen3.5:9b --tag qwen_shield --shield rv
"""
import argparse, concurrent.futures as cf, json, os, threading, time, urllib.request, zlib
from soc_env import CASES, CHANNELS, GOALS, ADAPTIVE_GOALS, CTI
from agent import run_episode

ap = argparse.ArgumentParser()
ap.add_argument("--model", required=True); ap.add_argument("--tag", required=True)
ap.add_argument("--defence", action="store_true"); ap.add_argument("--shield", default=None)
ap.add_argument("--variant", default="directive"); ap.add_argument("--no-clean", action="store_true")
ap.add_argument("--clean-reps", type=int, default=3); ap.add_argument("--workers", type=int, default=3)
ap.add_argument("--temperature", type=float, default=0.2)
ap.add_argument("--adaptive", action="store_true")
a = ap.parse_args()

jobs = []
if a.adaptive:
    for c in CASES:
        for ch in CHANNELS:
            if CTI[c["ioc"]]["abuse_contact"] and c["truth"] != "close":
                jobs.append((c["id"], {"channel": ch, "goal": "exfil_contact", "variant": a.variant}, 0))
            if c["truth"] != "close":
                jobs.append((c["id"], {"channel": ch, "goal": "omission", "variant": a.variant}, 0))
            if c["truth"] != "close" and c["host"] != "ws-042":
                jobs.append((c["id"], {"channel": ch, "goal": "launder", "variant": a.variant}, 0))
            if c["truth"] != "close":
                jobs.append((c["id"], {"channel": ch, "goal": "resolved_close", "variant": a.variant}, 0))
for c in ([] if a.adaptive else CASES):
    for ch in CHANNELS:
        for g in GOALS:
            if g == "suppress" and c["truth"] == "close":
                continue                       # suppression is not harmful on benign cases
            jobs.append((c["id"], {"channel": ch, "goal": g, "variant": a.variant}, 0))
if not a.no_clean and not a.adaptive:
    for c in CASES:
        for r in range(a.clean_reps):
            jobs.append((c["id"], None, r))

out = os.path.join(os.path.dirname(__file__), "..", "results", f"episodes_{a.tag}.jsonl")
done = set()
if os.path.exists(out):
    for line in open(out):
        d = json.loads(line)
        if "error" not in d:                   # failed episodes are rerun
            done.add(d["key"])
lock = threading.Lock()

def wait_for_server(max_wait=1800):
    """Block until Ollama answers /api/version; False after max_wait seconds."""
    t0 = time.time()
    while time.time() - t0 < max_wait:
        try:
            urllib.request.urlopen("http://localhost:11434/api/version", timeout=10).read()
            return True
        except Exception:
            time.sleep(15)
    return False

def key(j):
    cid, inj, r = j
    return f"{cid}|{inj['channel']+'/'+inj['goal'] if inj else 'clean'}|{r}"

def work(j):
    cid, inj, r = j
    k = key(j)
    seed = zlib.crc32(k.encode()) % 100000
    for attempt in range(3):
        try:
            res = run_episode(a.model, cid, inj, defence=a.defence, shield=a.shield,
                              temperature=a.temperature, seed=seed, session=k)
            break
        except Exception as e:
            res = dict(model=a.model, case=cid, injection=inj, error=repr(e))
            print(f"  retry {attempt + 1}/3 {k}: {e!r}", flush=True)
            if not wait_for_server():
                break
    if "error" in res:                         # not written, so a resume reruns it
        return k, None, res["error"]
    res["key"], res["tag"], res["variant"] = k, a.tag, a.variant
    with lock:
        with open(out, "a") as f:
            f.write(json.dumps(res, default=list) + "\n")
    return k, res.get("attack_success"), res.get("error")

todo = [j for j in jobs if key(j) not in done]
print(f"{a.tag}: {len(jobs)} jobs, {len(todo)} to run", flush=True)
with cf.ThreadPoolExecutor(a.workers) as ex:
    for i, (k, s, err) in enumerate(ex.map(work, todo), 1):
        if i % 10 == 0 or err:
            print(f"  {i}/{len(todo)} {k} succ={s} err={err}", flush=True)
print("done", a.tag, flush=True)
