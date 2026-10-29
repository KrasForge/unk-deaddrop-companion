import {Worker,isMainThread,parentPort,workerData} from 'node:worker_threads';
import fs from 'node:fs';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {version as acornVersion} from 'acorn';
import {performance} from 'node:perf_hooks';
import {parse as babelParse} from '@babel/parser';
import {inspect} from '../packages/unk-scanner/src/inspect.mjs';
import {ScannerPool,isolationProfile} from '../packages/unk-scanner/src/isolate.mjs';
const isolated=process.env.BENCH_MODE==='isolated';
const corpus=process.env.BENCH_CORPUS||'private-corpus';
const root=new URL('./',import.meta.url);
if(!isMainThread&&!isolated){
 parentPort.on('message',task=>{
  const start=performance.now(); let result; let source;
  try { source=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(fs.readFileSync(new URL(`${corpus}/${task.sha256}.source`,root))); const r=inspect(source,{filename:task.member});result={status:'parsed',parser:r.parser,findings:r.findings,artifactMatches:r.artifactMatches,deobfuscation:r.deobfuscation}; }
  catch(e){result={status:e instanceof SyntaxError?'parse-failure':'error',error:e.message};}
  result.scanElapsedMs=performance.now()-start;
  if(process.env.BENCH_VALIDATE==='1' && result.status==='parse-failure'){
   result.independentValidation={valid:false,parser:'@babel/parser 8.0.8',attempts:[]};
   const configurations=/\.tsx$/.test(task.member)?[['typescript','jsx']]:/\.[cm]?ts$/.test(task.member)?[['typescript']]:/\.jsx$/.test(task.member)?[['jsx']]:[[],['jsx']];
   for(const plugins of configurations){
    try{babelParse(source,{sourceType:'unambiguous',plugins});result.independentValidation={valid:true,parser:'@babel/parser 8.0.8',plugins};break;}
    catch(e){result.independentValidation.attempts.push({plugins,error:e.message});}
   }
  }
  parentPort.postMessage({...task,...result,elapsedMs:performance.now()-start});
 });
}else if(isMainThread){
 const receipts=JSON.parse(fs.readFileSync(new URL(process.env.BENCH_INPUT||'acquisition.json',root)));
 const tasks=[]; for(const r of receipts) for(const f of r.files||[]) if(f.status==='ready') tasks.push({ecosystem:r.ecosystem,package:r.name??r.dataset_path,version:r.version,...f});
 const unique=[...new Map(tasks.map(x=>[x.sha256,x])).values()];
 const workers=Math.max(1,Number(process.argv[2]||Math.min(4,os.availableParallelism())));
 const suffix=(process.env.BENCH_TAG||'')+(isolated?'-isolated':'')+(process.env.BENCH_VALIDATE==='1'?'-validated':'');
 const output=fs.createWriteStream(new URL(`results-${workers}${suffix}.jsonl`,root));
 const start=performance.now();let next=0,done=0;
 if(isolated){
  // Production path: the same isolated analysis processes the CLI uses.
  const pool=new ScannerPool({size:workers,timeoutMs:60000});
  await Promise.all(Array.from({length:workers},async()=>{
   while(next<unique.length){
    const task=unique[next++];const t0=performance.now();let result;
    try{const source=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(fs.readFileSync(new URL(`${corpus}/${task.sha256}.source`,root)));const r=await pool.scan(source,task.member);result={status:'parsed',parser:r.parser,findings:r.findings,artifactMatches:r.artifactMatches,deobfuscation:r.deobfuscation};}
    catch(e){result={status:e instanceof SyntaxError?'parse-failure':/timed out/.test(e.message)?'timeout':'error',error:e.message};}
    output.write(JSON.stringify({...task,...result,elapsedMs:performance.now()-t0})+'\n');done++;
   }
  }));
  pool.close();
 }else await Promise.all(Array.from({length:workers},()=>new Promise((resolve,reject)=>{
  let w,timer,active,finished=false;
  function record(r){output.write(JSON.stringify(r)+'\n');done++;}
  function send(){
   if(next>=unique.length){finished=true;w.terminate();resolve();return;}
   active=unique[next++];w.postMessage(active);
   timer=setTimeout(()=>fail('timeout','File exceeded 60 seconds'),60000);
  }
  function fail(status,error){
   if(finished||!active)return;
   clearTimeout(timer);record({...active,status,error});active=null;
   const previous=w;previous.removeAllListeners();previous.on('error',()=>{});previous.terminate();spawn();
  }
  function spawn(){
   w=new Worker(new URL(import.meta.url),{resourceLimits:{maxOldGenerationSizeMb:512}});
   w.on('error',e=>fail('worker-error',e.message));
   w.on('message',r=>{clearTimeout(timer);record(r);active=null;send();});
   w.on('exit',code=>{if(!finished&&active)fail('worker-error',`Unexpected worker exit ${code}`);});
   send();
  }
  spawn();
 })));
 await new Promise(r=>output.end(r));
 const seconds=(performance.now()-start)/1000;
 const scannerHash=createHash('sha256'); const srcRoot=new URL('../packages/unk-scanner/src/',root);
 for(const name of fs.readdirSync(srcRoot,{recursive:true}).filter(n=>n.endsWith('.mjs')).sort()){scannerHash.update(name+'\0');scannerHash.update(fs.readFileSync(new URL(name,srcRoot)));}
 const summary={harnessSha256:createHash('sha256').update(fs.readFileSync(new URL(import.meta.url))).digest('hex'),workerHeapMiB:512,perFileTimeoutSeconds:60,scannerSourceSha256:scannerHash.digest('hex'),acornVersion,node:process.version,os:os.platform(),architecture:os.arch(),availableParallelism:os.availableParallelism(),totalMemoryBytes:os.totalmem(),cpus:os.cpus()[0]?.model,workers,sourceOccurrences:tasks.length,uniqueFiles:unique.length,completed:done,seconds,filesPerSecond:done/seconds,bytesPerSecond:unique.reduce((n,x)=>n+x.bytes,0)/seconds,independentValidation:process.env.BENCH_VALIDATE==='1',scope:'read + UTF-8 decode + inspect + worker messaging + optional independent Babel validation on failures + JSONL write; excludes acquisition',scannerFallback:'Acorn, then @babel/parser 8.0.8 AST-only (TypeScript/JSX by file name)',input:process.env.BENCH_INPUT||'acquisition.json',corpus,mode:isolated?'isolated child processes (CLI path)':'in-process worker threads around inspect()',isolation:isolated?isolationProfile():null,statusCounts:null,failedPackages:receipts.filter(x=>x.status!=='downloaded').length};
 fs.writeFileSync(new URL(`summary-${workers}${suffix}.json`,root),JSON.stringify(summary,null,2));console.log(summary);
}
