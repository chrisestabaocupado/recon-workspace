import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { inspectKaliTools, probeTool } from '../src/server/kali-diagnostic.mjs';
import { KaliVerificationStore } from '../src/server/kali-access.ts';
import { kaliToolIssue, validateKaliTools } from '../src/lib/kali.ts';

const ssh={host:'192.0.2.20',port:22,username:'kali',privateKeyPath:'/synthetic/key',fingerprint:'SHA256:synthetic'};
const now=Date.now();

test('SearchSploit instalado: la ayuda termina con código 2 y no se interpreta como herramienta ausente',async()=>{
  const probe=(bin,args,code,text)=>probeTool(bin,args,()=>{
    const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>{};
    queueMicrotask(()=>{child.stdout.emit('data',Buffer.from(text));child.emit('close',code);});
    return child;
  });
  assert.equal((await probe('searchsploit',['-h'],2,'  Usage: searchsploit [options] term1\n')).status,'available');
  assert.equal((await probe('searchsploit',['--help'],2,'Usage: searchsploit [options]\n')).status,'available');
  assert.equal((await probe('searchsploit',['-h'],2,'ERROR: database unavailable\n')).status,'error');
  assert.equal((await probe('searchsploit',['-j','Apache'],2,'Usage: searchsploit [options]\n')).status,'error');
  assert.equal((await probe('nikto',['-h'],2,'Usage: searchsploit [options]\n')).status,'error');
  assert.equal((await probe('searchsploit',['-h'],1,'Usage: searchsploit [options]\n')).status,'error');
});

test('Verificar Kali detecta binarios ausentes y API local fallida sin consultar objetivos ni NVD',async()=>{
  const commands=[];
  const tools=await inspectKaliTools(async(bin,args)=>{
    commands.push([bin,args]);
    return {status:bin==='testssl'?'missing':'available',detail:bin==='testssl'?'testssl no está instalado o no está en PATH.':'Versión de prueba'};
  },async(url,options)=>{
    assert.equal(url,'http://127.0.0.1:5000/api/dbInfo');assert.equal(options.redirect,'error');
    throw new Error('Conexión rechazada');
  });
  assert.equal(commands.length,4);
  assert.deepEqual(commands.find(([bin])=>bin==='testssl'),['testssl',['--version']]);
  assert.equal(validateKaliTools(tools).length,6);
  assert.equal(tools.find(t=>t.tool==='testssl').status,'missing');
  assert.equal(tools.find(t=>t.tool==='cve').available,false);
  assert.equal(tools.find(t=>t.tool==='nvd').available,true);
  assert.match(tools.find(t=>t.tool==='nvd').detail,/No requiere instalar/);
  assert.match(kaliToolIssue(tools,'testssl'),/sudo apt install testssl.sh/);
  assert.equal(kaliToolIssue(tools,'nvd'),'');
});

test('La API local debe devolver JSON acotado, no basta una respuesta HTTP 200',async()=>{
  const probe=async()=>({status:'available',detail:'Versión'});
  for(const value of [new Response('<html>error</html>'),new Response('x'.repeat(16385)),new Response('null')]) {
    const tools=await inspectKaliTools(probe,async()=>value);
    assert.equal(tools.find(t=>t.tool==='cve').available,false);
  }
  const tools=await inspectKaliTools(probe,async()=>Response.json({database:'ready'}));
  assert.equal(tools.find(t=>t.tool==='cve').available,true);
});

test('Backend bloquea solo la herramienta ausente y exige volver a verificar después de instalar',async()=>{
  const tools=await inspectKaliTools(async(bin)=>({status:bin==='testssl'?'missing':'available',detail:'Estado de prueba'}),async()=>Response.json({db:'test'}));
  const store=new KaliVerificationStore();
  const verification=store.issue(ssh,now,tools);
  const access={mode:'ssh',ssh,kaliToken:verification.token};
  tools.find(t=>t.tool==='testssl').available=true;
  assert.deepEqual(store.require(access,now),access);
  assert.throws(()=>store.requireTool(access,'testssl',now),/no está instalado/);
  assert.deepEqual(store.requireTool(access,'nikto',now),access);
  assert.deepEqual(store.requireTool(access,'nvd',now),access);
  assert.throws(()=>store.requireTool({...access,ssh:{...ssh,host:'changed'}},'nvd',now),/verificación/);
  const refreshed=verification.tools.map(t=>t.tool==='testssl'?{...t,status:'available',available:true}:t);
  const next=store.issue(ssh,now,refreshed);
  assert.deepEqual(store.requireTool({...access,kaliToken:next.token},'testssl',now),{...access,kaliToken:next.token});
});

test('Diagnósticos incompletos o contradictorios no habilitan herramientas',async()=>{
  const tools=await inspectKaliTools(async()=>({status:'available',detail:'Versión'}),async()=>Response.json({db:'test'}));
  for(const rows of [[],tools.slice(1),[tools[0],...tools.slice(0,5)],tools.map(t=>({...t,status:'missing',available:true}))]) assert.throws(()=>validateKaliTools(rows));
  assert.match(kaliToolIssue(undefined,'testssl'),/Vuelve a comprobar/);
});

test('El probe diferencia ejecutable ausente, fallo y versión válida sin usar shell',async()=>{
  assert.equal((await probeTool(process.execPath,['--version'])).status,'available');
  assert.equal((await probeTool('one-two-three-missing-tool',['--version'])).status,'missing');
  assert.equal((await probeTool(process.execPath,['-e','process.exit(3)'])).status,'error');
});
