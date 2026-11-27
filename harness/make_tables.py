"""Write ../asr_table.tex and ../det_table.tex from ../results/summary.json (run analyze.py first).
Only configurations present in summary.json appear; missing ones are printed as PENDING rows."""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
S = json.load(open(os.path.join(HERE, "..", "results", "summary.json")))
CONFIGS = [("qwen_none", "Qwen3.5 9B", "--"), ("qwen_def", "Qwen3.5 9B", "delim."),
           ("phi4_none", "Phi-4 14B", "--"), ("phi4_def", "Phi-4 14B", "delim."),
           ("llama_none", "Llama 3.2 3B", "--"), ("llama_def", "Llama 3.2 3B", "delim."),
           ("qwen_forged", "Qwen3.5 9B", "forged"), ("qwen_shield", "Qwen3.5 9B", "RV shield")]
EXPECTED = 135  # injected episodes per complete configuration
DONE = {t for t in S if S[t]["n_attacked"] == EXPECTED and (S[t]["n_clean"] == 36 or t.endswith("_forged"))}
GOALS = ["hijack_protected", "hijack_unprotected", "suppress", "exfiltrate"]
MONS = [("stateless_loose", "Deny-list, loose"), ("stateless_strict", "Deny-list, strict"),
        ("percall_db", "Per-call, back end"), ("rv", "RV (P1--P5)"),
        ("rv_untyped", "RV, untyped"), ("rv_anytool", "RV, any tool"), ("rv_untimed", "RV, untimed")]


def kn(t):
    return f"{t[0]}/{t[1]}"


def pct(t):
    return f"{t[0]}/{t[1]} ({t[2][0]:.0f})"


rows = []
for tag, model, d in CONFIGS:
    if tag not in DONE:
        rows.append(f"{model} & {d} & \\multicolumn{{9}}{{c}}{{PENDING}} \\\\")
        continue
    s = S[tag]
    ch = s["asr_by_channel"]
    g = s["asr_by_goal"]
    clean = kn(s["clean_correct"]) if s["n_clean"] else "--"
    rows.append(" & ".join([model, d, pct(s["asr"]), kn(ch["alert"]), kn(ch["log"]), kn(ch["cti"])]
                           + [kn(g[x]) for x in GOALS] + [clean]) + " \\\\")
asr = r"""\begin{table*}[t]
\centering
\caption{Attack success. ASR is successful attacks over injected episodes (percent in
parentheses). Goals are protected hijack (HP), unprotected hijack (HU), suppression (S) and exfiltration (E).
Channels are the alert field, the log body and the CTI report narrative. Prompt is none (--), the prompt-level defence (delim.), the forged-structure injection (forged) or the monitor as in-loop shield (RV shield). Clean is clean episodes whose disposition and containment match ground truth (not run for forged).}
\label{tab:asr}
\footnotesize
\begin{tabular*}{\textwidth}{@{\extracolsep{\fill}}llrrrrrrrrr@{}}
\toprule
\textbf{Model} & \textbf{Prompt} & \textbf{ASR} & \textbf{alert} & \textbf{log} & \textbf{CTI} & \textbf{HP} & \textbf{HU} & \textbf{S} & \textbf{E} & \textbf{Clean} \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular*}
\end{table*}
"""
open(os.path.join(HERE, "..", "asr_table.tex"), "w").write(asr)

present = [c for c in CONFIGS if c[0] in DONE and S[c[0]]["n_clean"] and S[c[0]]["blocked_calls"] == 0]
models = []
for _, m, _ in present:
    if m not in models: models.append(m)
head = " & ".join(f"\\multicolumn{{{2 * sum(1 for c in present if c[1] == m)}}}{{c}}{{\\textbf{{{m}}}}}" for m in models)
cm1, col = "", 2
for m in models:
    n = 2 * sum(1 for c in present if c[1] == m)
    cm1 += f"\\cmidrule(lr){{{col}-{col + n - 1}}}"
    col += n
cm2 = "".join(f"\\cmidrule(lr){{{2 + 2 * i}-{3 + 2 * i}}}" for i in range(len(present)))
head2 = " & ".join(f"\\multicolumn{{2}}{{c}}{{{'none' if d == '--' else d}}}" for _, _, d in present)
sub = " & ".join(["det. & cl."] * len(present))
lines = []
for m, name in MONS:
    cells = []
    for tag, _, _ in present:
        r = S[tag]["monitors"][m]
        cells += [kn(r["detect"]), kn(r["clean_alarm"])]
    lines.append(name + " & " + " & ".join(cells) + " \\\\")
det = r"""\begin{table*}[t]
\centering
\caption{Pre-commit detection, replayed on the recorded traces. Column det.\ counts successful attacks whose harmful
call the monitor flags on the prefix before that call. Column cl.\ counts clean episodes with at least one
flagged action.}
\label{tab:det}
\footnotesize
\setlength{\tabcolsep}{3pt}
\begin{tabular*}{\textwidth}{@{\extracolsep{\fill}}l""" + "rr" * len(present) + r"""@{}}
\toprule
\textbf{Monitor} & """ + head + r""" \\
""" + cm1 + r"""
 & """ + head2 + r""" \\
""" + cm2 + r"""
 & """ + sub + r""" \\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular*}
\end{table*}
"""
open(os.path.join(HERE, "..", "det_table.tex"), "w").write(det)
print("wrote asr_table.tex, det_table.tex for", [c[0] for c in present])
