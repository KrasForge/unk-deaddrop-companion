"""Acquire the three-tier corpus as data only; nothing is installed or executed.

  tier1-npm         top 5,000 npm packages (npm-high-impact download ranking)
  tier1-marketplace top 1,000 VS Code Marketplace extensions by install count
  tier2             ~20,000 recently changed npm packages from the registry
                    changes feed, with weekly download counts for stratification
  tier3             Datadog malicious-packages dataset: every IDE-extension sample
                    and a seeded random sample of npm samples (encrypted zips,
                    read in memory; members written only as inert bytes)

Each subcommand writes tiers/<name>-manifest.json and tiers/<name>-acquisition.json.
Archives are read in memory with the same caps as acquire.py. Malicious members go
to private-malicious-DO-NOT-RUN/, never to private-corpus/.
"""
import concurrent.futures, datetime, hashlib, io, json, os, pathlib, random, re, subprocess, sys, tarfile, time
import urllib.error, urllib.parse, urllib.request, zipfile
from acquire import ROOT, DATA, LIMIT, fetch, js, acquire

TIERS = ROOT / 'tiers'; TIERS.mkdir(exist_ok=True)
MAL = ROOT / 'private-malicious-DO-NOT-RUN'
SOURCE = re.compile(r'\.(?:[cm]?js|jsx|[cm]?ts|tsx)$')
UA = {'User-Agent': 'unk-scanner-benchmark/1.0 (static research; contact via github.com/KrasForge)'}
now = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()


def request(url, data=None, headers=None, attempts=5):
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, data=data, headers={**UA, **(headers or {})})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read(LIMIT + 1)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                time.sleep(2 ** attempt * 3); continue
            raise


def write(name, manifest, rows):
    (TIERS / f'{name}-manifest.json').write_text(json.dumps(manifest, indent=1))
    (TIERS / f'{name}-acquisition.json').write_text(json.dumps(rows))
    status = {}
    for r in rows: status[r['status']] = status.get(r['status'], 0) + 1
    print(name, status, flush=True)


def run(items, worker=acquire, threads=16):
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        for row in pool.map(worker, items):
            rows.append(row)
            if len(rows) % 500 == 0: print(len(rows), flush=True)
    return rows


def tier1_npm():
    meta = js('https://registry.npmjs.org/npm-high-impact/latest'); data = fetch(meta['dist']['tarball'])
    archive = tarfile.open(fileobj=io.BytesIO(data))
    names = re.findall(r"^  '([^']+)'", archive.extractfile('package/lib/top-download.js').read().decode(), re.M)
    if len(names) < 5000: raise ValueError(f'ranking has only {len(names)} names')
    items = [dict(ecosystem='npm', name=n, rank=i + 1) for i, n in enumerate(names[:5000])]
    manifest = dict(retrieved=now(), ranking={'package': 'npm-high-impact', 'version': meta['version'],
                    'sha256': hashlib.sha256(data).hexdigest(), 'list': 'top-download.js', 'n': 5000}, items=items)
    write('tier1-npm', manifest, run(items))


GALLERY = 'https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery'


def tier1_marketplace():
    items, pages = [], []
    for page in range(1, 11):
        body = json.dumps({'filters': [{'criteria': [{'filterType': 8, 'value': 'Microsoft.VisualStudio.Code'},
                                                     {'filterType': 12, 'value': '4096'}],
                                        'pageNumber': page, 'pageSize': 100, 'sortBy': 4, 'sortOrder': 0}],
                           'flags': 0x1 | 0x2 | 0x10 | 0x80 | 0x100 | 0x200}).encode()
        result = json.loads(request(GALLERY, body, {'Content-Type': 'application/json',
                                                    'Accept': 'application/json;api-version=7.2-preview.1'}))
        extensions = result['results'][0]['extensions']; pages.append(len(extensions))
        for x in extensions:
            versions = x.get('versions') or []
            # Prefer a universal build, then linux-x64.
            version = next((v for v in versions if not v.get('targetPlatform')), None) or \
                next((v for v in versions if v.get('targetPlatform') == 'linux-x64'), None) or (versions[0] if versions else None)
            if not version: continue
            asset = next((f['source'] for f in version.get('files', []) if f['assetType'] == 'Microsoft.VisualStudio.Services.VSIXPackage'), None)
            installs = next((s['value'] for s in x.get('statistics', []) if s['statisticName'] == 'install'), None)
            items.append(dict(ecosystem='vs-marketplace', name=f"{x['publisher']['publisherName']}/{x['extensionName']}",
                              rank=len(items) + 1, version=version['version'], target=version.get('targetPlatform'),
                              url=asset, installs=installs, verified_publisher=x['publisher'].get('flags', '')))
        time.sleep(1)
    items = [i for i in items if i['url']][:1000]
    manifest = dict(retrieved=now(), source=GALLERY, query='VS Code target, excluding unpublished, sorted by install count',
                    page_sizes=pages, items=items)
    write('tier1-marketplace', manifest, run(items, threads=4))


def tier2():
    target = int(os.getenv('TIER2_N', '20000'))
    head = json.loads(request('https://replicate.npmjs.com/registry/_changes?limit=1&descending=true'))['last_seq']
    # The feed pages forward only; read ascending windows stepping back from the head.
    names, upper, step = {}, head, 50000
    while len(names) < target and upper > 0:
        lower = max(0, upper - step); seq = lower; window = {}
        while seq < upper:
            page = json.loads(request(f'https://replicate.npmjs.com/registry/_changes?limit=1000&since={seq}'))
            if not page['results']: break
            for change in page['results']:
                if change['seq'] > upper: break
                if change.get('deleted') or change['id'].startswith('_design'): continue
                window[change['id']] = change['seq']
            seq = page['results'][-1]['seq']
            if page['results'][-1]['seq'] >= upper: break
        for name, s in sorted(window.items(), key=lambda kv: -kv[1]):
            names.setdefault(name, s)
        print('window', lower, upper, 'unique', len(names), flush=True)
        upper = lower
    ordered = sorted(names.items(), key=lambda kv: -kv[1])[:target]
    names = dict(ordered); first_seq, last_seq = head, min(names.values())
    items = [dict(ecosystem='npm-recent', name=n, rank=i + 1, change_seq=s) for i, (n, s) in enumerate(names.items())]
    # Weekly downloads: bulk for unscoped names, one request each for scoped ones.
    downloads = {}
    unscoped = [i['name'] for i in items if not i['name'].startswith('@')]
    for k in range(0, len(unscoped), 128):
        try:
            data = json.loads(request('https://api.npmjs.org/downloads/point/last-week/' + ','.join(unscoped[k:k + 128])))
            for name, value in data.items(): downloads[name] = value['downloads'] if value else None
        except Exception: pass
    def scoped(name):
        try: return name, json.loads(request('https://api.npmjs.org/downloads/point/last-week/' + urllib.parse.quote(name, safe='@')))['downloads']
        except Exception: return name, None
    # Scoped names need one rate-limited request each; they are looked up later,
    # only for flagged packages and a random sample (TIER2_SCOPED=1 forces all).
    if os.getenv('TIER2_SCOPED') == '1':
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for name, value in pool.map(scoped, [i['name'] for i in items if i['name'].startswith('@')]): downloads[name] = value
    for item in items: item['weekly_downloads'] = downloads.get(item['name'])
    rows = run(items)
    # Publication time of the acquired version bounds the window.
    def published(row):
        if row['status'] != 'downloaded': return row
        try:
            meta = json.loads(request('https://registry.npmjs.org/' + urllib.parse.quote(row['name'], safe='@')))
            row['version_published'] = meta.get('time', {}).get(row['version'])
            row['package_created'] = meta.get('time', {}).get('created')
        except Exception: pass
        return row
    rows = run(rows, worker=published, threads=16)
    manifest = dict(retrieved=now(), source='https://replicate.npmjs.com/registry/_changes (descending)',
                    seq_range=[last_seq, first_seq], n=len(items), items=items)
    write('tier2', manifest, rows)


DATASET = 'https://github.com/DataDog/malicious-software-packages-dataset.git'


def tier3():
    n_npm = int(os.getenv('TIER3_NPM', '2000'))
    clone = ROOT / 'datadog-dataset-DO-NOT-RUN'
    git = lambda *a: subprocess.run(['git', '-C', str(clone), *a], check=True, capture_output=True, text=True).stdout
    if not clone.exists():
        subprocess.run(['git', 'clone', '--filter=blob:none', '--no-checkout', '--depth', '1', DATASET, str(clone)], check=True)
    commit = git('rev-parse', 'HEAD').strip()
    paths = git('ls-tree', '-r', '--name-only', 'HEAD', 'samples').splitlines()
    # npm and PyPI samples are encrypted zips; IDE extensions are stored as .vsix.
    zips = [p for p in paths if p.endswith('.zip') or (p.split('/')[1] == 'ide_extensions' and p.endswith('.vsix'))]
    ecosystems = sorted({p.split('/')[1] for p in zips})
    ide = [p for p in zips if p.split('/')[1] == 'ide_extensions']
    npm = sorted(p for p in zips if p.split('/')[1] == 'npm')
    sample = sorted(random.Random(20261029).sample(npm, min(n_npm, len(npm))))
    chosen = ide + sample
    git('sparse-checkout', 'init', '--no-cone')
    (clone / '.git' / 'info' / 'sparse-checkout').write_text('\n'.join('/' + p for p in chosen) + '\n')
    git('checkout', 'HEAD')
    MAL.mkdir(exist_ok=True)
    rows = []
    for p in chosen:
        row = dict(ecosystem=p.split('/')[1], category=p.split('/')[2], dataset_path=p, files=[])
        try:
            outer = zipfile.ZipFile(clone / p)
            total = 0
            stack = [(outer, b'infected')]
            while stack:
                archive, pwd = stack.pop()
                for info in archive.infolist():
                    if info.is_dir() or info.file_size > 64 * 1024 * 1024: continue
                    name = info.filename
                    if name.lower().endswith(('.vsix', '.zip')) or (name.lower().endswith(('.tgz', '.tar.gz'))):
                        blob = archive.read(info, pwd=pwd)
                        if name.lower().endswith(('.tgz', '.tar.gz')):
                            tar = tarfile.open(fileobj=io.BytesIO(blob))
                            for m in tar.getmembers():
                                if m.isfile() and SOURCE.search(m.name) and m.size <= 8 * 1024 * 1024:
                                    src = tar.extractfile(m).read(); total += len(src)
                                    sha = hashlib.sha256(src).hexdigest(); (MAL / (sha + '.source')).write_bytes(src)
                                    row['files'].append(dict(member=f'{name}!{m.name}', sha256=sha, bytes=len(src), status='ready'))
                        else:
                            stack.append((zipfile.ZipFile(io.BytesIO(blob)), None))
                        continue
                    if not SOURCE.search(name): continue
                    if info.file_size > 8 * 1024 * 1024:
                        row['files'].append(dict(member=name, status='oversize', bytes=info.file_size)); continue
                    src = archive.read(info, pwd=pwd); total += len(src)
                    if total > 512 * 1024 * 1024: raise ValueError('expansion cap')
                    sha = hashlib.sha256(src).hexdigest(); dest = MAL / (sha + '.source')
                    if not dest.exists(): dest.write_bytes(src)
                    row['files'].append(dict(member=name, sha256=sha, bytes=len(src), status='ready'))
            row['status'] = 'downloaded'
        except Exception as e:
            row.update(status='failed', error=str(e)[:200])
        rows.append(row)
    manifest = dict(retrieved=now(), dataset=DATASET, commit=commit, license='Apache-2.0', ecosystems=ecosystems,
                    zips_total=len(zips), ide_samples=len(ide), npm_samples_total=len(npm), npm_sampled=len(sample),
                    seed=20261029, chosen=chosen)
    write('tier3', manifest, rows)


if __name__ == '__main__':
    {'tier1-npm': tier1_npm, 'tier1-marketplace': tier1_marketplace, 'tier2': tier2, 'tier3': tier3}[sys.argv[1]]()
