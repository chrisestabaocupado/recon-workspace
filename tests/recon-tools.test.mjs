import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectKaliTools, probeTool } from '../src/server/kali-diagnostic.mjs';
import { KaliVerificationStore } from '../src/server/kali-access.ts';
import { kaliToolIssue, validateKaliTools } from '../src/lib/kali.ts';

const ssh={host:'192.0.2.20',port:22,username:'kali',privateKeyPath:'/synthetic/key',fingerprint:'SHA256:synthetic'};
const now=Date.now();

test('El diagnóstico solo comprueba herramientas auxiliares de reconocimiento, sin consultas de red',async()=>{
  const commands=[];
  const tools=await inspectKaliTools(async(bin,args)=>{
    commands.push([bin,args]);
    return {status:bin==='dig'?'missing':'available',detail:'Diagnóstico local'};
  });
  assert.deepEqual(commands,[['dig',['-v']],['openssl',['version']]]);
  assert.equal(validateKaliTools(tools).length,2);
  assert.match(kaliToolIssue(tools,'dig'),/sudo apt install bind9-dnsutils/);
  assert.equal(kaliToolIssue(tools,'openssl'),'');
});

test('El backend vincula la disponibilidad al diagnóstico y exige verificar tras instalar',async()=>{
  const tools=await inspectKaliTools(async bin=>({status:bin==='dig'?'missing':'available',detail:'Versión'}));
  const store=new KaliVerificationStore();
  const verification=store.issue(ssh,now,tools);
  const access={mode:'ssh',ssh,kaliToken:verification.token};
  tools.find(t=>t.tool==='dig').available=true;
  assert.deepEqual(store.require(access,now),access);
  assert.throws(()=>store.requireTool(access,'dig',now),/no está instalado/);
  assert.deepEqual(store.requireTool(access,'openssl',now),access);
  assert.throws(()=>store.requireTool({...access,ssh:{...ssh,host:'changed'}},'openssl',now),/verificación/);
  const refreshed=verification.tools.map(t=>({...t,status:'available',available:true}));
  const next=store.issue(ssh,now,refreshed);
  assert.deepEqual(store.requireTool({...access,kaliToken:next.token},'dig',now),{...access,kaliToken:next.token});
});

test('Diagnósticos incompletos, duplicados o contradictorios no se aceptan',async()=>{
  const tools=await inspectKaliTools(async()=>({status:'available',detail:'Versión'}));
  for(const rows of [[],tools.slice(1),[tools[0],tools[0]],tools.map(t=>({...t,status:'missing',available:true}))]) assert.throws(()=>validateKaliTools(rows));
  assert.match(kaliToolIssue(undefined,'dig'),/Vuelve a comprobar/);
});

test('El probe diferencia ejecutable ausente, fallo y versión válida sin usar shell',async()=>{
  assert.equal((await probeTool(process.execPath,['--version'])).status,'available');
  assert.equal((await probeTool('recon-workspace-missing-tool',['--version'])).status,'missing');
  assert.equal((await probeTool(process.execPath,['-e','process.exit(3)'])).status,'error');
});
