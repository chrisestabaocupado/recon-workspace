import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { installCommands, installationLog, installStep, installTools } from '../src/server/remote-install.mjs';
import { KaliInstallManager } from '../src/server/kali-install-manager.ts';
import { KaliVerificationStore } from '../src/server/kali-access.ts';
import { validateKaliInstallInput } from '../src/server/kali-install-input.ts';
import { execJsonEvents } from '../src/server/ssh.ts';

const tick=()=>new Promise(resolve=>setImmediate(resolve));
const ssh={host:'192.0.2.20',port:22,username:'kali',privateKeyPath:'/synthetic/key',fingerprint:'SHA256:synthetic'};

test('La instalación exige SSH verificado, catálogo fijo y herramientas ausentes según el servidor',()=>{
  const store=new KaliVerificationStore();
  const verified=store.issue(ssh,Date.now(),[{tool:'testssl',status:'missing',available:false,detail:'missing',database:''},{tool:'nikto',status:'available',available:true,detail:'installed',database:''}]);
  const input={mode:'ssh',ssh,kaliToken:verified.token,tools:['testssl'],sudoPassword:'synthetic-secret'};
  assert.deepEqual(validateKaliInstallInput(input,store).tools,['testssl']);
  for(const patch of [{mode:'local'},{kaliToken:'00000000-0000-4000-8000-000000000000'},{tools:['nikto']},{tools:['cve']},{tools:['--allow-unauthenticated']},{tools:['testssl','testssl']},{sudoPassword:'bad\npassword'}]) assert.throws(()=>validateKaliInstallInput({...input,...patch},store));
});

test('APT no recibe entradas arbitrarias, no elimina paquetes y la contraseña no va en argv',()=>{
  const commands=installCommands(['testssl','searchsploit'],'synthetic-secret',false);
  assert.equal(commands[0][0],'sudo');assert.deepEqual(commands[0][1].slice(0,5),['-S','-k','-p','','--']);
  assert.ok(!JSON.stringify(commands).includes('synthetic-secret'));
  assert.ok(commands[1][1].includes('--no-remove'));
  assert.deepEqual(commands[1][1].slice(-2),['testssl.sh','exploitdb']);
  assert.equal(installCommands(['trivy'],'',true)[0][0],'apt-get');
  assert.equal(installCommands(['trivy'],'',false)[0][1][0],'-n');
  for(const tools of [['testssl; echo unsafe'],['nvd'],[],['testssl','testssl']]) assert.throws(()=>installCommands(tools));
});

test('El runner detiene la secuencia si update falla y limpia la contraseña',async()=>{
  const events=[],calls=[];
  const request={tools:['testssl'],sudoPassword:'synthetic-secret'};
  await installTools(request,e=>events.push(e),async(bin,args,password)=>{calls.push({bin,args,password});return 100;},false);
  assert.equal(calls.length,1);assert.equal(events.at(-1).code,100);assert.equal(request.sudoPassword,'');
  assert.ok(!JSON.stringify(events).includes('synthetic-secret'));
  const success=[];
  await installTools({tools:['testssl']},e=>success.push(e),async()=>0,true);
  assert.equal(success.at(-1).code,0);assert.equal(success.filter(e=>e.type==='stage').length,2);
});

test('Contraseñas partidas entre chunks y líneas extensas nunca salen en el progreso',()=>{
  const output=[];
  const log=installationLog('synthetic-secret',text=>output.push(text));
  log('Preparando synthetic-');assert.equal(output.length,0);
  log('secret\n');log('Fin synthetic-secret',true);
  assert.equal(output.join(''),'Preparando [oculto]\nFin [oculto]');
  log('x'.repeat(17000));log('synthetic-secret\nOK\n',true);
  assert.ok(!output.join('').includes('synthetic-secret'));assert.match(output.join(''),/omitida/);
});

test('Sudo recibe contraseña solo por stdin, sin shell ni PTY y conserva UTF-8',async()=>{
  const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.stdin=new EventEmitter();
  let input='';child.stdin.end=value=>{input=value;queueMicrotask(()=>{const bytes=Buffer.from('Instalación ñ\n');child.stdout.emit('data',bytes.subarray(0,bytes.length-2));child.stdout.emit('data',bytes.subarray(bytes.length-2));child.emit('close',0);});};
  const events=[];
  const code=await installStep('sudo',['-S'],'synthetic-secret',e=>events.push(e),(bin,args,options)=>{assert.equal(options.shell,false);assert.equal(options.env.DEBIAN_FRONTEND,'noninteractive');assert.ok(!args.includes('synthetic-secret'));return child;});
  assert.equal(code,0);assert.equal(input,'synthetic-secret\n');assert.match(events[0].data,/Instalación ñ/);
});

test('El gestor vincula progreso a la conexión, impide solapamientos y conserva fallos o resultado desconocido',async()=>{
  const manager=new KaliInstallManager();let emit,complete;
  const first=manager.start('owner',['testssl'],e=>{emit=e;return new Promise(resolve=>{complete=resolve;});});
  assert.throws(()=>manager.get(first.id,'other'),/no existe/);
  assert.throws(()=>manager.start('owner',['nikto'],async()=>{}),/curso/);
  emit({type:'log',data:'password=do-not-save\n'});emit({type:'done',code:0,error:''});complete();await tick();
  const saved=manager.get(first.id,'owner');assert.equal(saved.state,'completed');assert.ok(!saved.logs.includes('do-not-save'));
  saved.tools.push('nikto');assert.deepEqual(manager.get(first.id,'owner').tools,['testssl']);
  const failed=manager.start('owner',['testssl'],async e=>{e({type:'done',code:100,error:'APT bloqueado'});});await tick();assert.equal(manager.get(failed.id,'owner').state,'failed');
  const lost=manager.start('owner',['testssl'],async()=>{throw new Error('SSH lost');});await tick();assert.equal(manager.get(lost.id,'owner').state,'unknown');
});

test('El transporte envía el secreto como datos y exige cierre confirmado con eventos JSON',async()=>{
  const connection=new EventEmitter(),stream=new EventEmitter();stream.stderr=new EventEmitter();stream.stderr.resume=()=>{};stream.close=()=>{};
  connection.exec=(command,callback)=>{assert.ok(!command.includes('synthetic-secret'));callback(null,stream);};
  stream.end=input=>{assert.equal(JSON.parse(input).sudoPassword,'synthetic-secret');queueMicrotask(()=>{const data=Buffer.from(JSON.stringify({type:'log',data:'Instalación ñ'})+'\n'+JSON.stringify({type:'done',code:0})+'\n');for(const byte of data)stream.emit('data',Buffer.from([byte]));stream.emit('close',0);});};
  const events=[];await execJsonEvents(connection,'// fixed program',{sudoPassword:'synthetic-secret'},new AbortController().signal,e=>events.push(e));
  assert.equal(events[0].data,'Instalación ñ');assert.equal(events[1].code,0);
  assert.equal(connection.listenerCount('close'),0);
});
