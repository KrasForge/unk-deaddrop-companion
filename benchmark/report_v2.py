"""Summarise the scanner 0.2.0 corpus run and write the review ledger.

Reads results-4-v2-validated.jsonl (in-process run with independent Babel
validation of rejected files), the two run summaries and reviewed-v2.json.
Writes analysis-v2.json and review-ledger-v2.csv. Corpus source is not copied.
"""
import collections, csv, json, pathlib

ROOT = pathlib.Path(__file__).resolve().parent
rows = [json.loads(line) for line in (ROOT / 'results-4-v2-validated.jsonl').read_text().splitlines()]
acquisition = json.loads((ROOT / 'acquisition.json').read_text())
reviews = json.loads((ROOT / 'reviewed-v2.json').read_text())
summaries = {tag: json.loads((ROOT / f'summary-4-v2-{tag}.json').read_text()) for tag in ('validated', 'isolated')}
isolated_rows = [json.loads(line) for line in (ROOT / 'results-4-v2-isolated.jsonl').read_text().splitlines()]

ecosystem_of = {}
for package in acquisition:
    for f in package['files']:
        if f['status'] == 'ready':
            ecosystem_of.setdefault(f['sha256'], set()).add(package['ecosystem'])


def extension(member):
    name = member.rsplit('/', 1)[-1]
    return name.rsplit('.', 1)[-1].lower() if '.' in name else ''


def coverage(selected):
    status = collections.Counter(r['status'] for r in selected)
    failures = [r for r in selected if r['status'] == 'parse-failure']
    js = [r for r in selected if extension(r['member']) in ('js', 'mjs', 'cjs')]
    js_fail = [r for r in js if r['status'] == 'parse-failure']
    js_valid_fail = [r for r in js_fail if r.get('independentValidation', {}).get('valid')]
    return {
        'unique_files': len(selected),
        'status': dict(status),
        'parse_failures_by_extension': dict(collections.Counter(extension(r['member']) for r in failures)),
        'rejected_but_valid_under_babel': sum(r.get('independentValidation', {}).get('valid', False) for r in failures),
        'javascript_files': len(js),
        'javascript_parse_failures': len(js_fail),
        'javascript_failures_valid_under_babel': len(js_valid_fail),
    }


def findings(selected):
    table = collections.defaultdict(lambda: {'instances': 0, 'files': set(), 'packages': set()})
    for r in selected:
        for f in r.get('findings', []):
            entry = table[(f['kind'], f['severity'])]
            entry['instances'] += 1
            entry['files'].add(r['sha256'])
            entry['packages'].add(r['package'])
    return {f'{k}:{s}': {'instances': v['instances'], 'files': len(v['files']), 'packages': len(v['packages'])}
            for (k, s), v in sorted(table.items())}


review_index = {(r['sha256'], r['kind'], r['line'], r['column']): r for r in reviews['findings']}
package_reviews = reviews['packages']
ledger = []
for r in rows:
    for f in r.get('findings', []):
        if f['severity'] == 'note':
            continue
        note = review_index.get((r['sha256'], f['kind'], f['line'], f['column'])) or \
            package_reviews.get(f"{f['kind']}|{r['package']}")
        ledger.append({
            'sha256': r['sha256'], 'package': r['package'], 'version': r['version'], 'member': r['member'],
            'kind': f['kind'], 'severity': f['severity'], 'line': f['line'], 'column': f['column'],
            'detail': f['detail'][:200],
            'decision': note['decision'] if note else 'unreviewed',
            'rationale': note['rationale'] if note else '',
        })
with (ROOT / 'review-ledger-v2.csv').open('w', newline='') as out:
    writer = csv.DictWriter(out, fieldnames=list(ledger[0].keys()) if ledger else ['sha256'])
    writer.writeheader()
    writer.writerows(ledger)

deobfuscation = collections.Counter((d['variant'], d['method']) for r in rows for d in r.get('deobfuscation') or [])
call_sites = sum(d['callSites'] for r in rows for d in r.get('deobfuscation') or [])
decoded = sum(d['decodedSites'] for r in rows for d in r.get('deobfuscation') or [])
times = sorted(r['scanElapsedMs'] for r in rows if r['status'] == 'parsed')
pct = lambda p: round(times[min(len(times) - 1, int(len(times) * p))], 2)
analysis = {
    'corpus': {eco: dict(collections.Counter(p['status'] for p in acquisition if p['ecosystem'] == eco)) for eco in ('npm', 'open-vsx')},
    'source_occurrences': summaries['validated']['sourceOccurrences'],
    'coverage': {
        'all': coverage(rows),
        'npm': coverage([r for r in rows if 'npm' in ecosystem_of.get(r['sha256'], ())]),
        'open-vsx': coverage([r for r in rows if 'open-vsx' in ecosystem_of.get(r['sha256'], ())]),
    },
    'findings': findings(rows),
    'review': dict(collections.Counter(f"{e['kind']}:{e['severity']}:{e['decision']}" for e in ledger)),
    'deobfuscation': {'arrays': {f'{v}:{m}': n for (v, m), n in sorted(deobfuscation.items())}, 'call_sites': call_sites, 'decoded': decoded},
    'scan_time_ms_parsed_files': {'median': pct(0.5), 'p95': pct(0.95), 'p99': pct(0.99), 'max': round(times[-1])},
    'runs': {tag: {k: s[k] for k in ('mode', 'workers', 'uniqueFiles', 'completed', 'seconds', 'filesPerSecond', 'bytesPerSecond', 'node', 'cpus', 'scannerSourceSha256', 'harnessSha256', 'isolation') if k in s}
             for tag, s in summaries.items()},
    'isolated_status': dict(collections.Counter(r['status'] for r in isolated_rows)),
    'isolated_findings': findings(isolated_rows),
}
(ROOT / 'analysis-v2.json').write_text(json.dumps(analysis, indent=2))
print(json.dumps(analysis, indent=2))
