# Compare frozen-engine and mitigated-engine results file by file (keyed by sha256).
# Usage: mitdiff.py FROZEN.jsonl MITIGATED.jsonl OUT.json
import json, sys, collections
rank = {'none': 0, 'note': 1, 'warning': 2, 'error': 3}
def alerts(rec):
    return sorted({(f['kind'], f['severity']) for f in rec.get('findings') or [] if f['severity'] != 'note'})
def top(a):
    return max((rank[s] for _, s in a), default=0)
frozen = {}
with open(sys.argv[1]) as fh:
    for line in fh:
        r = json.loads(line)
        a = alerts(r)
        frozen[r['sha256']] = (top(a), a, r.get('status'))
changes = collections.Counter(); kinds = collections.Counter(); samples = []
total = 0; packages_up = collections.defaultdict(set)
with open(sys.argv[2]) as fh:
    for line in fh:
        r = json.loads(line); total += 1
        old = frozen.get(r['sha256'])
        if old is None: changes['missing-in-frozen'] += 1; continue
        a = alerts(r); new = top(a)
        if r.get('status') != old[2]: changes[f"status {old[2]}->{r.get('status')}"] += 1
        if new == old[0] and a == old[1]: continue
        added = [x for x in a if x not in old[1]]
        direction = 'up' if new > old[0] else 'down' if new < old[0] else 'same-level'
        changes[direction] += 1
        for k in added: kinds[f'{k[0]}:{k[1]}'] += 1
        if direction == 'up': packages_up[[k for k in rank if rank[k] == new][0]].add(r.get('package'))
        if len(samples) < 400:
            samples.append({'direction': direction, 'package': r.get('package'), 'member': r.get('member'), 'sha256': r['sha256'],
                            'before': old[1], 'after': a,
                            'details': [f"{f['kind']}:{f['severity']}:{f['line']}: {f['detail'][:220]}" for f in r.get('findings') or []
                                        if f['severity'] != 'note' and (f['kind'], f['severity']) in added]})
out = {'files': total, 'changes': dict(changes), 'addedAlerts': dict(kinds),
       'packagesRaisedTo': {k: len(v) for k, v in packages_up.items()}, 'samples': samples}
json.dump(out, open(sys.argv[3], 'w'), indent=1)
print(json.dumps({k: out[k] for k in ('files', 'changes', 'addedAlerts', 'packagesRaisedTo')}, indent=1))
