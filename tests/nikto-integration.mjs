// Explicit opt-in: npm run test:nikto on Kali. All requests stay on loopback.
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { defaultAnalysisQuery, parseAnalysisReport, appendAnalysis, validateAnalysisData } from '../src/lib/analysis.ts';
import { executeAnalysis, runTool, toolArguments } from '../src/server/remote-analysis.mjs';

const spawnNikto = (bin, args, options) => process.env.NIKTO_SCRIPT
  ? spawn('perl', [process.env.NIKTO_SCRIPT, ...args], options)
  : spawn(bin, args, options);
const runner = (bin,args,ms,cwd) => runTool(bin,args,ms,cwd,spawnNikto);

test('Nikto real: HTTP, JSON 2.6, candidatas, evidencia y persistencia, solo loopback', async () => {
  const fixture=http.createServer((_req,res)=>{
    res.writeHead(404,{'Server':'local-test-fixture','Content-Type':'text/html'});
    res.end('<html><h1>Not Found</h1></html>');
  });
  await new Promise(resolve=>fixture.listen(0,'127.0.0.1',resolve));
  try {
    const q={...defaultAnalysisQuery(),tool:'nikto',target:'127.0.0.1',port:fixture.address().port,tls:false,timeoutSeconds:25};
    const r=await executeAnalysis(q,runner);
    assert.equal(r.reportAvailable,true,r.error+'\n'+r.stderr+'\n'+r.stdout);
    const report=JSON.parse(r.raw);
    const host=Array.isArray(report)?report[0]:report;
    assert.equal(host.ip,'127.0.0.1');
    assert.match(r.stdout,/Target IP:\s+127\.0\.0\.1/);
    const findings=parseAnalysisReport('nikto',r.raw);
    const evidence={id:'local-fixture',tool:'nikto',target:q.target,port:q.port,query:'local fixture',date:new Date().toISOString(),raw:r.raw,warnings:[],error:r.error};
    const saved=validateAnalysisData(JSON.parse(JSON.stringify(appendAnalysis(undefined,evidence,findings))));
    assert.equal(saved.evidence[0].raw,r.raw);
    assert.equal(saved.findings.length,findings.length);
    assert.ok(r.error,'A bounded scan must remain partial');
  } finally {
    fixture.closeAllConnections();
    await new Promise(resolve=>fixture.close(resolve));
  }
});

test('Nikto real: SIGINT conserva JSON antes del corte final', async () => {
  const fixture=http.createServer((_req,res)=>{ res.writeHead(200,{'Server':'local-test-fixture'}); res.end('local fixture'); });
  await new Promise(resolve=>fixture.listen(0,'127.0.0.1',resolve));
  const dir=await mkdtemp(path.join(os.tmpdir(),'nikto-loopback-'));
  try {
    const report=path.join(dir,'report.json');
    const q={...defaultAnalysisQuery(),tool:'nikto',target:'127.0.0.1',port:fixture.address().port,tls:false,timeoutSeconds:60};
    const [bin,args]=toolArguments(q,report);
    const r=await runner(bin,args,12000,dir);
    assert.match(r.error,/Tiempo agotado/);
    const raw=await readFile(`${report}.json`,'utf8').catch(()=>readFile(report,'utf8'));
    assert.doesNotThrow(()=>JSON.parse(raw));
    assert.notEqual(r.code,null,'Child must exit during graceful shutdown');
  } finally {
    fixture.closeAllConnections();
    await new Promise(resolve=>fixture.close(resolve));
    await rm(dir,{recursive:true,force:true});
  }
});

test('Nikto real: HTTPS y certificado del servicio local', async () => {
  const dir=await mkdtemp(path.join(os.tmpdir(),'nikto-tls-loopback-'));
  let fixture;
  try {
    const key=path.join(dir,'key.pem'), cert=path.join(dir,'cert.pem');
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=localhost'],{stdio:'ignore'});
    fixture=https.createServer({key:await readFile(key),cert:await readFile(cert)},(_req,res)=>{
      res.writeHead(404,{'Server':'local-tls-fixture'});res.end('Not Found');
    });
    await new Promise(resolve=>fixture.listen(0,'127.0.0.1',resolve));
    const r=await executeAnalysis({...defaultAnalysisQuery(),tool:'nikto',target:'127.0.0.1',port:fixture.address().port,tls:true,timeoutSeconds:25},runner);
    assert.equal(r.reportAvailable,true,r.error+'\n'+r.stderr+'\n'+r.stdout);
    const report=JSON.parse(r.raw);
    const host=Array.isArray(report)?report[0]:report;
    assert.equal(host.ip,'127.0.0.1');
    assert.match(r.stdout,/SSL Info/);
    assert.ok(!host.vulnerabilities.some(v=>v.id==='FAIL'));
    assert.doesNotThrow(()=>parseAnalysisReport('nikto',r.raw));
  } finally {
    if(fixture){fixture.closeAllConnections();await new Promise(resolve=>fixture.close(resolve));}
    await rm(dir,{recursive:true,force:true});
  }
});

test('Nikto real: URL de dominio conserva Host y SNI con TCP fijado a loopback', async () => {
  const dir=await mkdtemp(path.join(os.tmpdir(),'nikto-domain-loopback-'));
  let fixture;
  try {
    const key=path.join(dir,'key.pem'), cert=path.join(dir,'cert.pem');
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=webmail.lab.invalid'],{stdio:'ignore'});
    const options={key:await readFile(key),cert:await readFile(cert)};
    const context=tls.createSecureContext(options);
    const requests=[];
    fixture=https.createServer({...options,SNICallback:(name,done)=>done(name==='webmail.lab.invalid'?null:new Error('wrong SNI'),context)},(req,res)=>{
      requests.push({host:req.headers.host,sni:req.socket.servername,path:req.url});
      res.writeHead(404,{'Server':'local-vhost-fixture'});res.end('Not Found');
    });
    await new Promise(resolve=>fixture.listen(0,'127.0.0.1',resolve));
    const port=fixture.address().port;
    const r=await executeAnalysis({...defaultAnalysisQuery(),tool:'nikto',target:`https://webmail.lab.invalid:${port}/webmail/`,timeoutSeconds:45},runner,'127.0.0.1');
    assert.equal(r.reportAvailable,true,r.error+'\n'+r.stderr+'\n'+r.stdout);
    assert.equal(r.pinnedAddress,'127.0.0.1');
    assert.ok(requests.length>0,'Nikto must reach the local virtual host');
    assert.ok(requests.every(req=>req.sni==='webmail.lab.invalid'));
    assert.ok(requests.every(req=>req.host===`webmail.lab.invalid:${port}` || req.host==='webmail.lab.invalid'));
    assert.ok(requests.some(req=>new URL(req.path,`https://webmail.lab.invalid:${port}`).pathname.startsWith('/webmail')),JSON.stringify(requests)+'\n'+r.stdout+'\n'+r.stderr);
    assert.doesNotThrow(()=>parseAnalysisReport('nikto',r.raw));
    assert.ok(!JSON.parse(r.raw)[0].vulnerabilities.some(v=>v.id==='FAIL'));
  } finally {
    if(fixture){fixture.closeAllConnections();await new Promise(resolve=>fixture.close(resolve));}
    await rm(dir,{recursive:true,force:true});
  }
});
