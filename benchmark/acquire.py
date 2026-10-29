"""Download ranked artifacts as data only; never install or execute corpus packages."""
import concurrent.futures, hashlib, io, json, pathlib, re, tarfile, urllib.request, zipfile, datetime, time, os
ROOT=pathlib.Path(__file__).resolve().parent
DATA=ROOT/'private-corpus'; DATA.mkdir(exist_ok=True)
LIMIT=256*1024*1024

def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'unk-scanner-benchmark/1.0'}),timeout=90) as r:
        if int(r.headers.get('Content-Length','0'))>LIMIT: raise ValueError('archive exceeds 256 MiB cap (Content-Length)')
        started=time.monotonic(); chunks=[]; size=0
        while True:
            chunk=r.read(1024*1024)
            if not chunk: break
            chunks.append(chunk); size+=len(chunk)
            if size>LIMIT: raise ValueError('archive exceeds 256 MiB cap')
            if time.monotonic()-started>120: raise TimeoutError('archive download exceeds 120 seconds')
        data=b''.join(chunks)
    if len(data)>LIMIT: raise ValueError('archive exceeds 256 MiB cap')
    # Some registries (VS Marketplace) send gzip transfer encoding; zip and tar
    # archives never start with the gzip magic, so decode it here.
    if data[:2]==b'\x1f\x8b' and 'gzip' in (r.headers.get('Content-Encoding') or ''):
        import gzip; data=gzip.decompress(data)
        if len(data)>LIMIT: raise ValueError('archive exceeds 256 MiB cap')
    return data

def js(url): return json.loads(fetch(url))

def acquire(item):
    ident=hashlib.sha256((item['ecosystem']+':'+item['name']).encode()).hexdigest()
    receipt=DATA/(ident+'.json')
    if receipt.exists():
        cached=json.loads(receipt.read_text())
        if cached['status']=='downloaded' or os.getenv('BENCH_RETRY_FAILED')!='1': return cached
    row=dict(item); row['files']=[]
    try:
        if item['ecosystem'].startswith('npm'):
            meta=js('https://registry.npmjs.org/'+urllib.parse.quote(item['name'],safe='')+'/latest')
            row.update(version=meta['version'],url=meta['dist']['tarball'],integrity=meta['dist'].get('integrity'))
        data=fetch(row['url']); row['archive_sha256']=hashlib.sha256(data).hexdigest()
        if row['ecosystem'].startswith('npm'):
            archive=tarfile.open(fileobj=io.BytesIO(data)); members=[(x.name,x.size,x) for x in archive.getmembers() if x.isfile()]
            read=lambda x: archive.extractfile(x).read(8*1024*1024+1)
        else:
            archive=zipfile.ZipFile(io.BytesIO(data)); members=[(x.filename,x.file_size,x) for x in archive.infolist() if not x.is_dir()]
            read=lambda x: archive.open(x).read(8*1024*1024+1)
        total=0
        for name,size,entry in members:
            if not re.search(r'\.(?:[cm]?js|jsx|[cm]?ts|tsx)$',name): continue
            if size>8*1024*1024:
                row['files'].append(dict(member=name,status='oversize',bytes=size));continue
            total+=size
            if total>512*1024*1024: raise ValueError('source expansion exceeds 512 MiB cap')
            source=read(entry); sha=hashlib.sha256(source).hexdigest(); path=DATA/(sha+'.source')
            if not path.exists(): path.write_bytes(source)
            row['files'].append(dict(member=name,sha256=sha,bytes=len(source),status='ready'))
        row['status']='downloaded'
    except Exception as e: row.update(status='failed',error=str(e))
    temporary=receipt.with_suffix('.tmp'); temporary.write_text(json.dumps(row)); temporary.replace(receipt); return row

if __name__=='__main__':
    import urllib.parse
    manifest=ROOT/'manifest.json'
    if not manifest.exists():
        meta=js('https://registry.npmjs.org/npm-high-impact/latest'); data=fetch(meta['dist']['tarball'])
        archive=tarfile.open(fileobj=io.BytesIO(data))
        names=re.findall(r"^  '([^']+)'",archive.extractfile('package/lib/top-download.js').read().decode(),re.M)[:2500]
        if len(names)!=2500: raise ValueError('ranking contains fewer than 2500 names')
        items=[dict(ecosystem='npm',name=n,rank=i+1) for i,n in enumerate(names)]
        snapshots=[]; seen=set()
        for offset in range(0,500,100):
            page=js(f'https://open-vsx.org/api/-/search?size=100&offset={offset}&sortBy=downloadCount&sortOrder=desc'); snapshots.append(page)
            for x in page['extensions']:
                name=x['namespace']+'/'+x['name']
                if name in seen: raise ValueError('duplicate extension in ranking pagination')
                seen.add(name); items.append(dict(ecosystem='open-vsx',name=name,rank=len(seen),version=x['version'],url=x['files']['download'],downloads=x['downloadCount']))
        manifest.write_text(json.dumps(dict(retrieved=datetime.datetime.now(datetime.timezone.utc).isoformat(),npm_ranking={'package':'npm-high-impact','version':meta['version'],'sha256':hashlib.sha256(data).hexdigest(),'qualification':'Published ranking snapshot, not a verified current global top 2500'},openvsx_snapshots=snapshots,items=items),indent=2))
    items=json.loads(manifest.read_text())['items']
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        rows=[]
        for row in pool.map(acquire,items):
            rows.append(row)
            if len(rows)%50==0: print(len(rows),row['ecosystem'],row['status'],flush=True)
    (ROOT/'acquisition.json').write_text(json.dumps(rows,indent=2))
