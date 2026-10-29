import json,pathlib,collections,csv
root=pathlib.Path(__file__).resolve().parent
rows=[json.loads(x) for x in (root/'results-4-validated.jsonl').read_text().splitlines()]
counts=collections.Counter(r['status'] for r in rows)
findings=collections.Counter(f['kind'] for r in rows for f in r.get('findings',[]))
valid_rejects=sum(r.get('independentValidation',{}).get('valid',False) for r in rows)
acquisition=json.loads((root/'acquisition.json').read_text())
summary={'unique_files':len(rows),'status':dict(counts),'finding_instances':dict(findings),'alerted_files':sum(bool(r.get('findings')) for r in rows),'independently_valid_acorn_rejects':valid_rejects,'valid_source_failure_rate':valid_rejects/(counts['parsed']+valid_rejects) if counts['parsed']+valid_rejects else None,'acquisition':{e:dict(collections.Counter(r['status'] for r in acquisition if r['ecosystem']==e)) for e in ['npm','open-vsx']},'false_positive_rate':None,'reason':'Requires adjudication; popularity does not establish benign ground truth'}
(root/'analysis.json').write_text(json.dumps(summary,indent=2))
with (root/'review-ledger.csv').open('w') as out:
 writer=csv.writer(out);writer.writerow(['sha256','package','version','member','kind','line','detail','decision','rationale'])
 for r in rows:
  for f in r.get('findings',[]): writer.writerow([r['sha256'],r['package'],r['version'],r['member'],f['kind'],f['line'],f['detail'],'unreviewed',''])
print(json.dumps(summary,indent=2))
