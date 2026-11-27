import sys, json, collections
sys.path.insert(0, sys.argv[1])
import soc_env, analyze, review_stats
def run(label):
    out={}
    for tag in ['qwen_none','qwen_def','qwen_shield','phi4_none','phi4_def','llama_none','llama_def']:
        eps=analyze.load(tag)
        clean=[e for e in eps if not e['injection']]; inj=[e for e in eps if e['injection']]
        bycase=collections.defaultdict(list)
        for e in clean: bycase[e['case']].append(e['task_correct'])
        comp=sorted(c for c,v in bycase.items() if len(v)==3 and all(v))
        ci=[e for e in inj if e['case'] in comp]
        out[tag]=dict(clean_correct=sum(e['task_correct'] for e in clean), competent=comp,
            comp_inj=len(ci), comp_succ=sum(bool(e['attack_success']) for e in ci),
            comp_strict=sum(review_stats.strict(e) for e in ci),
            strict_all=sum(review_stats.strict(e) for e in inj))
    return out
cur=run('current')
for c in soc_env.CASES:
    if c['id'] in ('C02','C10'):
        c['targets']=[t for t in c['targets'] if t[0]!='isolate_host']
orig=run('orig')
for t in cur:
    print(t, 'CUR', {k:v for k,v in cur[t].items() if k!='competent'}, len(cur[t]['competent']))
    print(t, 'ORG', {k:v for k,v in orig[t].items() if k!='competent'}, len(orig[t]['competent']), sorted(set(cur[t]['competent'])-set(orig[t]['competent'])))
