"""Summarise the controlled string-array recovery experiment.

Reads results-<tool>.jsonl and samples-<label>.json; writes summary.json and
prints tables by tool and obfuscator version, and by option for each tool.
"""
import collections
import json
import sys

TOOLS = ['scanner-frozen', 'scanner-hardened', 'webcrack', 'synchrony', 'obfuscator-io-deobfuscator']
samples = {}
for label in ('v5', 'v4'):
    for s in json.load(open(f'samples-{label}.json'))['samples']:
        samples[s['id']] = s


def stats(rows):
    done = [r for r in rows if 'error' not in r]
    hidden = sum(r['hidden'] for r in done)
    recovered = sum(r['recovered'] for r in done)
    return {
        'samples': len(rows),
        'errors': len(rows) - len(done),
        'hidden': hidden,
        'recovered': recovered,
        'recall': round(recovered / hidden, 4) if hidden else None,
        'complete': sum(1 for r in done if r['hidden'] and r['recovered'] == r['hidden']),
        'samplesWithWrong': sum(1 for r in done if r['wrong']),
        'wrongStrings': sum(r['wrong'] for r in done),
        'medianMs': sorted(r['ms'] for r in done)[len(done) // 2] if done else None,
    }


results = {}
for tool in TOOLS:
    try:
        lines = open(f'results-{tool}.jsonl').read().splitlines()
    except FileNotFoundError:
        continue
    rows = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # a tool's own log line, left when the 60 s limit killed it
    # Samples without a result line timed out or crashed.
    expected = open('ids.txt' if tool.startswith('scanner') else 'ids-subset.txt').read().split()
    seen = {r['id'] for r in rows}
    rows += [{'tool': tool, 'id': i, 'error': 'timeout or crash'} for i in expected if i not in seen]
    results[tool] = rows

summary = {'byToolVersion': {}, 'byOption': {}, 'scannerMethods': {}, 'wrongExamples': {}}
for tool, rows in results.items():
    for label in ('v5', 'v4'):
        part = [r for r in rows if r['id'].startswith(label)]
        summary['byToolVersion'][f'{tool}/{label}'] = stats(part)
    for option in ('encoding', 'rotate', 'wrappers', 'callsTransform', 'indexShift'):
        groups = collections.defaultdict(list)
        for r in rows:
            s = samples[r['id']]
            groups[f"{s['label']}:{option}={s[option]}"].append(r)
        summary['byOption'].setdefault(tool, {}).update({k: stats(v) for k, v in sorted(groups.items())})
    if tool.startswith('scanner'):
        methods = collections.Counter()
        for r in rows:
            arrays = r.get('arrays') or []
            methods[(r['id'][:2], arrays[0]['method'] if arrays else 'not found')] += 1
        summary['scannerMethods'][tool] = {f'{k[0]}:{k[1]}': v for k, v in sorted(methods.items())}
    examples = collections.Counter()
    for r in rows:
        for w in r.get('wrongExamples') or []:
            examples[w] += 1
    summary['wrongExamples'][tool] = examples.most_common(8)

json.dump(summary, open('summary.json', 'w'), indent=1)
print(f"{'tool/version':40} {'n':>5} {'err':>4} {'recall':>7} {'complete':>8} {'wrongS':>6} {'wrongStr':>8} {'ms':>6}")
for key, s in summary['byToolVersion'].items():
    print(f"{key:40} {s['samples']:5} {s['errors']:4} {str(s['recall']):>7} {s['complete']:8} {s['samplesWithWrong']:6} {s['wrongStrings']:8} {str(s['medianMs']):>6}")
if len(sys.argv) > 1:
    for tool in sys.argv[1:]:
        print('\n' + tool)
        for key, s in summary['byOption'].get(tool, {}).items():
            print(f"  {key:32} recall={s['recall']} complete={s['complete']}/{s['samples']} wrongSamples={s['samplesWithWrong']} errors={s['errors']}")
        print('  methods', summary['scannerMethods'].get(tool))
        print('  wrong', summary['wrongExamples'].get(tool))
