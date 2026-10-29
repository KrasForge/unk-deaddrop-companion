// Scan the retained investigation artifacts in isolated processes and compare
// each file's maximum severity with the expected value. Nothing is executed.
import fs from 'node:fs';
import {ScannerPool,isolationProfile} from '../packages/unk-scanner/src/isolate.mjs';
const dir=new URL('./private-artifacts-DO-NOT-RUN/',import.meta.url);
const index=JSON.parse(fs.readFileSync(new URL('index.json',dir))).map(a=>({...a,expectedMaxSeverity:a.expectedMaxSeverity??'none'}));
const rank={none:0,note:1,warning:2,error:3};
const pool=new ScannerPool({size:2,timeoutMs:60000});
const files=[];
for(const a of index){
 const r=await pool.scan(fs.readFileSync(new URL(`${a.sha256}.source`,dir),'utf8'),a.member);
 const alerts=r.findings.filter(f=>f.severity!=='note').map(f=>`${f.kind}:${f.severity}`);
 const maxSeverity=r.findings.reduce((m,f)=>rank[f.severity]>rank[m]?f.severity:m,'none');
 files.push({sha256:a.sha256,role:a.role,expectedMaxSeverity:a.expectedMaxSeverity,maxSeverity,match:maxSeverity===a.expectedMaxSeverity,alerts:[...new Set(alerts)],parser:r.parser,
  deobfuscation:(r.deobfuscation||[]).map(({strings,...d})=>d)});
}
pool.close();
const out={date:new Date().toISOString(),note:'Static analysis of retained investigation artifacts in isolated processes; nothing was executed. Paths omitted.',isolation:isolationProfile(),matched:files.filter(f=>f.match).length,total:files.length,files};
fs.writeFileSync(new URL('artifact-sensitivity-server.json',import.meta.url),JSON.stringify(out,null,1));
console.log(`${out.matched}/${out.total} match expected severity`);
for(const f of files) console.log(f.match?'ok ':'DIFF',f.maxSeverity.padEnd(8),f.role);
