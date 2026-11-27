"""Table of the scripted temporal workload from ../results/temporal_suite.json -> ../temporal_table.tex."""
import json, os
H = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(H, "..", "results", "temporal_suite.json")))
assert d["py_mp_agree"]["v2"] == d["total"]["n"]
LABEL = {
    "verdict retracted, re-retrieved": "Retracted, looked up again",
    "verdict retracted, feed notification": "Retracted, notification",
    "verdict retracted in back end only": "Retracted in back end only",
    "retracted in back end only, after 30 min": "\\quad same, after 30\\,min",
    "unchanged verdict, after 30 min": "Unchanged, after 30\\,min",
    "verdict upgraded": "Raised to malicious",
    "approval age 5, 15, 15 min + 1 s": "Approval aged 5, 15, 15\\,min+1\\,s",
    "approval revoked, notification": "Approval revoked, notification",
    "approval revoked in back end only": "Revoked in back end only",
    "approval for another object": "Approval for other object",
    "burst, 45 s apart": "4 blocks 45\\,s apart",
    "burst within one second": "4 blocks in 1\\,s",
    "burst, fourth at 600 s and 601 s": "4th block at 600, 601\\,s",
    "indicator never looked up": "Indicator not looked up",
}
cols = ["mp_v1", "py_v1", "py_v2", "untimed", "percall", "backend"]
rows = []
for k, f in d["families"].items():
    rows.append(f"{LABEL[k]} & {f['n']} & " + " & ".join(str(f[c]) for c in cols) + r" \\")
t = d["total"]
tex = r"""\begin{table}[t]
\centering
\caption{Correct decisions on the scripted temporal workload ($n$ labelled decisions). Ref.: Python
monitor of the live runs. Once: MonPoly, window $[1\,\mathrm{s},10\,\mathrm{min}]$. Cur.: current-record
semantics (Python and MonPoly agree on all 36). Unt.: Cur.\ without time bounds. Call, State: per-call
and stateful back-end policies.}
\label{tab:temporal}
\footnotesize
\setlength{\tabcolsep}{2.2pt}
\begin{tabular}{@{}lrrrrrrr@{}}
\toprule
\textbf{Scenario} & $\boldsymbol{n}$ & \textbf{Once} & \textbf{Ref.} & \textbf{Cur.} & \textbf{Unt.} & \textbf{Call} & \textbf{State} \\
\midrule
""" + "\n".join(rows) + r"""
\midrule
Total & """ + f"{t['n']} & " + " & ".join(str(t[c]) for c in cols) + r""" \\
\bottomrule
\end{tabular}
\end{table}
"""
open(os.path.join(H, "..", "temporal_table.tex"), "w").write(tex)
print(tex)
