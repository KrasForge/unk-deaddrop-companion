"""Produce portable metadata and measurements without redistributing corpus code."""
import collections,csv,gzip,json,pathlib,hashlib
p=pathlib.Path(__file__).resolve().parent
acq=json.loads((p/'acquisition.json').read_text())
rows=[json.loads(x) for x in (p/'results-4-validated.jsonl').read_text().splitlines()]
byhash={r['sha256']:r for r in rows}
review={ (r['sha256'],r['kind'],r['line'],r['column']):r for r in json.loads((p/'reviewed-npm-findings.json').read_text())}
with gzip.open(p/'corpus-receipts.json.gz','wt') as out:json.dump(acq,out)
with gzip.open(p/'file-results.jsonl.gz','wt') as out:
 for r in rows:out.write(json.dumps(r)+'\n')
sections=[]
for eco in ['npm','open-vsx']:
 subset=[r for r in acq if r['ecosystem']==eco]
 hashes={f['sha256'] for r in subset for f in r['files'] if f['status']=='ready'}
 selected=[byhash[h] for h in hashes]
 count=collections.Counter(r['status'] for r in selected)
 findings=collections.Counter(f['kind'] for r in selected for f in r.get('findings',[]))
 sections.append(dict(ecosystem=eco,selected_packages=len(subset),acquisition_status=dict(collections.Counter(r['status'] for r in subset)),packages_without_sources=sum(not any(f['status']=='ready' for f in r['files']) for r in subset),excluded_sources=sum(f['status']!='ready' for r in subset for f in r['files']),unique_files=len(hashes),status=dict(count),valid_rejects=sum(r.get('independentValidation',{}).get('valid',False) for r in selected),findings=dict(findings),alerted_files=sum(bool(r.get('findings')) for r in selected)))
(p/'coverage.json').write_text(json.dumps(sections,indent=2))
with (p/'review-ledger.csv').open('w') as out:
 writer=csv.writer(out);writer.writerow(['sha256','package','version','member','kind','line','column','decision','reviewer','rationale'])
 for r in rows:
  for f in r.get('findings',[]):
   note=review.get((r['sha256'],f['kind'],f['line'],f['column']),{})
   writer.writerow([r['sha256'],r['package'],r['version'],r['member'],f['kind'],f['line'],f['column'],note.get('decision','unreviewed'),note.get('reviewer',''),note.get('rationale','')])
print(json.dumps(sections,indent=2))
