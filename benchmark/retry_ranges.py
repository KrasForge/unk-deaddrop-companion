"""Retrieve source members from failed VSIX downloads using bounded HTTP ranges."""
import concurrent.futures,hashlib,io,json,pathlib,re,urllib.request,zipfile,collections
from acquire import DATA,ROOT
BLOCK=1024*1024
class Remote(io.RawIOBase):
 def __init__(self,url):
  r=urllib.request.urlopen(urllib.request.Request(url,headers={'Range':'bytes=0-0'}),timeout=30)
  if r.status!=206: r.close();raise ValueError('server does not support ranges')
  self.size=int(r.headers['Content-Range'].split('/')[-1]);self.url=r.url;self.etag=r.headers.get('ETag');r.close();self.pos=0;self.cache=collections.OrderedDict()
 def seekable(self):return True
 def readable(self):return True
 def tell(self):return self.pos
 def seek(self,offset,whence=0):
  self.pos=offset if whence==0 else self.pos+offset if whence==1 else self.size+offset
  if self.pos<0:raise ValueError('negative seek')
  return self.pos
 def read(self,n=-1):
  end=self.size if n<0 else min(self.pos+n,self.size)
  if end-self.pos>32*BLOCK:raise ValueError('ZIP metadata/read exceeds 32 MiB bound')
  out=[]
  while self.pos<end:
   index=self.pos//BLOCK
   if index not in self.cache:
    start=index*BLOCK;last=min(start+BLOCK,self.size)-1
    with urllib.request.urlopen(urllib.request.Request(self.url,headers={'Range':f'bytes={start}-{last}'}),timeout=60) as r:
     if r.status!=206 or r.headers.get('Content-Range')!=f'bytes {start}-{last}/{self.size}':raise ValueError('inconsistent range response')
     if self.etag and r.headers.get('ETag')!=self.etag:raise ValueError('ETag changed during retrieval')
     data=r.read(BLOCK+1)
     if len(data)!=last-start+1:raise ValueError('truncated or oversized range')
    self.cache[index]=data
    if len(self.cache)>32:self.cache.popitem(last=False)
   data=self.cache[index];count=min(end-self.pos,len(data)-self.pos%BLOCK);out.append(data[self.pos%BLOCK:self.pos%BLOCK+count]);self.pos+=count
  return b''.join(out)

def retry(item):
 ident=hashlib.sha256((item['ecosystem']+':'+item['name']).encode()).hexdigest();path=DATA/(ident+'.json')
 if path.exists() and json.loads(path.read_text())['status']=='downloaded':return
 row=dict(item,files=[])
 try:
  remote=Remote(item['url']);archive=zipfile.ZipFile(remote);row.update(acquisition_method='HTTP range ZIP source-member retrieval',archive_bytes=remote.size,archive_etag=remote.etag,archive_sha256=None);total=0
  for x in archive.infolist():
   if x.is_dir() or not re.search(r'\.(?:[cm]?js|jsx|[cm]?ts|tsx)$',x.filename):continue
   if x.file_size>8*BLOCK:row['files'].append(dict(member=x.filename,status='oversize',bytes=x.file_size));continue
   total+=x.file_size
   if total>512*BLOCK:raise ValueError('source expansion exceeds 512 MiB cap')
   source=archive.read(x);sha=hashlib.sha256(source).hexdigest();dest=DATA/(sha+'.source')
   if not dest.exists():dest.write_bytes(source)
   row['files'].append(dict(member=x.filename,status='ready',bytes=len(source),sha256=sha))
  row['status']='downloaded'
 except Exception as e:row.update(status='failed',error=str(e))
 tmp=path.with_suffix('.range-tmp');tmp.write_text(json.dumps(row));tmp.replace(path)
 print(item['name'],row['status'],len(row['files']),row.get('error',''),flush=True)

if __name__=='__main__':
 items=json.loads((ROOT/'manifest.json').read_text())['items']
 with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:list(pool.map(retry,[x for x in items if x['ecosystem']=='open-vsx']))
 rows=[json.loads((DATA/(hashlib.sha256((x['ecosystem']+':'+x['name']).encode()).hexdigest()+'.json')).read_text()) for x in items]
 (ROOT/'acquisition.json').write_text(json.dumps(rows,indent=2))
