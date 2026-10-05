import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { analysisCommand, analysisInventory, analysisQueryIssues, appendAnalysis, defaultAnalysisQuery, emptyAnalysis, parseAnalysisReport, toolRecommendations, validateAnalysisData, validateAnalysisQuery } from '../src/lib/analysis.ts';
import { makeFailure } from '../src/lib/operation-history.ts';
import { approveScopePlan, newScopePlan, validateScopePlan } from '../src/lib/scope.ts';
import { exportWorkspace, importWorkspace } from '../src/lib/storage.ts';
import { projectCheckAttempts, projectChecklist } from '../src/lib/test-checklist.ts';
import { executeAnalysis, niktoProxy, runTool, toolArguments } from '../src/server/remote-analysis.mjs';
import http from 'node:http';
import net from 'node:net';
import { analysisQueryWithPort, analysisQueryWithTls, analysisQueryWithTarget, analysisResolvedAddress } from '../src/lib/analysis.ts';
import { parseNiktoTarget } from '../src/lib/web-target.mjs';

const now = Date.parse('2026-10-02T12:00:00Z');
const project = { id:'lab', name:'Laboratorio', scope:'192.0.2.0/24', createdAt:new Date(now).toISOString(), targets:[], executions:0 };
const evidence = { id:'e1', tool:'searchsploit', target:'192.0.2.10', query:'searchsploit -j Apache', date:new Date(now).toISOString(), raw:'{"RESULTS_EXPLOIT":[]}', warnings:[], error:'' };
const finding = { title:'Referencia de prueba', description:'Revisar CVE-2021-44228', severity:'HIGH', recommendation:'Verificar condiciones', cves:['CVE-2021-44228'] };
test('URL Nikto conserva dominio y ruta, ajusta HTTPS/puerto y rechaza entradas ambiguas', () => {
  let q = analysisQueryWithTarget({...defaultAnalysisQuery(),tool:'nikto',port:80,tls:false},'https://webmail.lab.test/webmail/');
  assert.equal(q.port,443);assert.equal(q.tls,true);
  assert.deepEqual(parseNiktoTarget(q),{host:'webmail.lab.test',port:443,tls:true,root:'/webmail/',url:'https://webmail.lab.test:443/webmail/'});
  const args=toolArguments(validateAnalysisQuery(q),'/tmp/report')[1];
  assert.ok(args.includes('https://webmail.lab.test:443')); assert.equal(args[args.indexOf('-root')+1],'/webmail/');
  assert.match(analysisCommand(q),/-root \/webmail\//);
  q=analysisQueryWithPort(q,8443);assert.equal(parseNiktoTarget(q).port,8443);
  q=analysisQueryWithTls(q,false);assert.equal(parseNiktoTarget(q).tls,false);assert.equal(parseNiktoTarget(q).port,8443);
  for (const target of ['ftp://lab.test/','https://user:secret@lab.test/','https://lab.test/?x=1','https://lab.test/#a','lab.test/path','192.0.2.0/24','https://lab.test:99999/'])
    assert.throws(()=>validateAnalysisQuery({...q,target}));
});
test('Dominio requiere inclusión exacta; DNS de Kali se fija y respeta exclusiones IP y alias', () => {
  const q={...defaultAnalysisQuery(),tool:'nikto',target:'https://webmail.lab.test/webmail/'};
  const plan={...approved(),includes:['webmail.lab.test']};
  assert.deepEqual(analysisQueryIssues(q,plan,now),[]);
  assert.ok(analysisQueryIssues(q,approved(),now).length);
  assert.equal(analysisResolvedAddress(q,plan,{'webmail.lab.test':['192.0.2.10']}),'192.0.2.10');
  assert.throws(()=>analysisResolvedAddress(q,plan,{'webmail.lab.test':['192.0.2.99']}),/excluido/);
  assert.throws(()=>analysisResolvedAddress(q,plan,{'webmail.lab.test':[]}),/resolver/);
  assert.throws(()=>analysisResolvedAddress(q,plan,{'webmail.lab.test':['192.0.2.10','invalid']}),/inválida/);
  assert.throws(()=>analysisResolvedAddress(q,{...plan,excludes:['blocked.lab.test']},{'webmail.lab.test':['192.0.2.10'],'blocked.lab.test':['192.0.2.10']}),/excluido/);
  assert.throws(()=>analysisResolvedAddress(q,{...plan,excludes:['blocked.lab.test']},{'webmail.lab.test':['192.0.2.10']}),/resolver/);
  assert.ok(analysisQueryIssues({...q,target:'https://webmail.lab.test:8443/'},plan,now).some(issue=>issue.includes('Puerto')));
});
test('Dominio sin IP autorizada no inicia Nikto', async () => {
  let ran=false;
  await assert.rejects(()=>executeAnalysis({...defaultAnalysisQuery(),tool:'nikto',target:'https://webmail.lab.test/'},async()=>{ran=true;}),/resolverse y autorizarse/);
  assert.equal(ran,false);
});
test('El programa enviado por SSH incluye el parser de URL y bloquea dominios sin IP fijada', async () => {
  const source=await readFile(new URL('../src/server/remote-analysis.mjs',import.meta.url),'utf8');
  const parser=await readFile(new URL('../src/lib/web-target.mjs',import.meta.url),'utf8');
  const program=source.replace('import { parseNiktoTarget } from "../lib/web-target.mjs";',parser.replace('export function parseNiktoTarget','function parseNiktoTarget'));
  assert.ok(!program.includes('../lib/web-target.mjs'));
  const result=spawnSync(process.execPath,['--input-type=module','-e',program],{input:JSON.stringify({operation:'run',query:{...defaultAnalysisQuery(),tool:'nikto',target:'https://webmail.lab.invalid/'}}),encoding:'utf8',timeout:5000});
  assert.equal(result.status,1);assert.match(result.stderr,/resolverse y autorizarse/);
});
test('Conexión HTTP conserva Host, fija IP y rechaza otros hosts/puertos sin seguir redirecciones',async () => {
  const requests=[];
  const fixture=http.createServer((req,res)=>{requests.push({host:req.headers.host,path:req.url});res.writeHead(302,{Location:'https://other.lab.test/'});res.end('redirect');});
  await new Promise(resolve=>fixture.listen(0,'127.0.0.1',resolve));
  const port=fixture.address().port;
  const proxy=await niktoProxy(parseNiktoTarget({target:`http://unresolvable.invalid:${port}/webmail/`,tls:false,port}),'127.0.0.1');
  const request=url=>new Promise((resolve,reject)=>{const req=http.request(proxy.url,{path:url},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.end();});
  try {
    assert.equal(await request(`http://unresolvable.invalid:${port}/webmail/`),302);
    assert.deepEqual(requests,[{host:`unresolvable.invalid:${port}`,path:'/webmail/'}]);
    assert.equal(await request(`http://other.lab.test:${port}/`),403);
    assert.equal(await request(`http://unresolvable.invalid:${port+1}/`),403);
    assert.equal(requests.length,1);
    const answer=await new Promise((resolve,reject)=>{const socket=net.connect(new URL(proxy.url).port,'127.0.0.1',()=>socket.write('CONNECT other.lab.test:443 HTTP/1.1\r\n\r\n'));socket.on('data',data=>{resolve(data.toString());socket.destroy();});socket.on('error',reject);});
    assert.match(answer,/403 Forbidden/);
  } finally {await proxy.close();fixture.closeAllConnections();await new Promise(resolve=>fixture.close(resolve));}
});
test('Túnel HTTPS solo permite CONNECT al dominio/puerto fijado', async () => {
  let connections=0;
  const fixture=net.createServer(socket=>{connections++;socket.write('pinned target');});
  await new Promise(resolve=>fixture.listen(0,'127.0.0.1',resolve));
  const port=fixture.address().port;
  const proxy=await niktoProxy(parseNiktoTarget({target:`https://unresolvable.invalid:${port}/`,tls:true,port}),'127.0.0.1');
  const connect=authority=>new Promise((resolve,reject)=>{
    let response='';
    const socket=net.connect(new URL(proxy.url).port,'127.0.0.1',()=>socket.write(`CONNECT ${authority} HTTP/1.1\r\n\r\n`));
    socket.setTimeout(2000,()=>socket.destroy(new Error('test timeout')));
    socket.on('error',reject);
    socket.on('data',data=>{response+=data.toString();if(response.includes('403 Forbidden') || response.includes('pinned target')){resolve(response);socket.destroy();}});
  });
  try {
    assert.match(await connect(`other.invalid:${port}`),/403/);
    assert.match(await connect(`unresolvable.invalid:${port+1}`),/403/);
    assert.equal(connections,0);
    const response=await connect(`unresolvable.invalid:${port}`);
    assert.match(response,/200 Connection Established/);assert.match(response,/pinned target/);assert.equal(connections,1);
  } finally {await proxy.close();await new Promise(resolve=>fixture.close(resolve));}
});
test('Nikto sugiere HTTP en 80 y HTTPS en 443, permite ajustes y reserva tiempo para guardar JSON', () => {
  let q = analysisQueryWithPort({...defaultAnalysisQuery(), tool:'nikto', target:'192.0.2.10'},80);
  assert.equal(q.tls,false);
  assert.match(analysisCommand(q),/http:\/\/192\.0\.2\.10:80/);
  q = {...q, tls:true};
  assert.match(analysisCommand(q),/https:\/\/192\.0\.2\.10:80/);
  assert.equal(analysisQueryWithPort(q,8080).tls,true);
  assert.equal(analysisQueryWithPort({...q,tls:false},443).tls,true);
  const https=analysisQueryWithTls({...q,port:80,tls:false},true);
  assert.equal(https.port,443); assert.equal(https.tls,true);
  assert.match(analysisCommand(https),/https:\/\/192\.0\.2\.10:443/);
  assert.ok(toolArguments(https,'/tmp/report.json')[1].includes('https://192.0.2.10:443'));
  const http=analysisQueryWithTls(https,false);
  assert.equal(http.port,80); assert.equal(http.tls,false);
  for(const port of [8080,8443]) {
    assert.equal(analysisQueryWithTls({...q,port},true).port,port);
    assert.equal(analysisQueryWithTls({...q,port},false).port,port);
  }
  const args = toolArguments(q,'/tmp/report.json')[1];
  assert.ok(args.includes('-nocheck'));
  assert.equal(args[args.indexOf('-maxtime')+1],'45s');
  assert.match(analysisCommand(q),/-maxtime 45s/);
  assert.ok(args.includes('-ssl'));
  assert.ok(toolArguments({...q,tls:false},'/tmp/report.json')[1].includes('-nossl'));
  assert.equal(toolArguments({...q,timeoutSeconds:5},'/tmp/report.json')[1].includes('1s'),true);
});
test('Nikto sin JSON conserva el diagnóstico original incluso con código cero o timeout', async () => {
  const q = {...defaultAnalysisQuery(),tool:'nikto',target:'192.0.2.10',port:80,tls:false};
  for (const result of [
    {stdout:'+ ERROR: Cannot connect to host',stderr:'',code:0,error:''},
    {stdout:'',stderr:'Unknown option: badflag',code:2,error:''},
    {stdout:'Scan incomplete',stderr:'',code:null,error:'Tiempo agotado'},
  ]) {
    const r = await executeAnalysis(q,async()=>({...result}));
    assert.equal(r.reportAvailable,false);
    assert.match(r.error,/no generó el reporte JSON/);
    assert.ok(r.error.includes(result.error || result.stderr || result.stdout));
    assert.ok(!r.error.includes('ENOENT'));
    assert.equal(r.raw,result.stdout);
  }
});
test('Nikto con JSON conserva reporte y consola independientemente', async () => {
  const raw = JSON.stringify({vulnerabilities:[{id:'1',msg:'Revisar configuración'}]});
  const r = await executeAnalysis({...defaultAnalysisQuery(),tool:'nikto',target:'192.0.2.10'},async (_bin,args)=>{
    await writeFile(args[args.indexOf('-output')+1],raw);
    return {stdout:'Scan completed',stderr:'Diagnostic',code:0,error:''};
  });
  assert.equal(r.reportAvailable,true); assert.equal(r.raw,raw);
  assert.equal(r.stdout,'Scan completed'); assert.equal(r.stderr,'Diagnostic');
  assert.equal(parseAnalysisReport('nikto',r.raw).length,1);
});
test('Nikto 2.6 agrega extensión al output; se recoge su JSON y se conservan candidatas parciales', async () => {
  const raw=JSON.stringify([{host:'192.0.2.10',ip:'192.0.2.10',port:'80',vulnerabilities:[{id:'1',url:'/',msg:'Header missing'}]}]);
  const r=await executeAnalysis({...defaultAnalysisQuery(),tool:'nikto',target:'192.0.2.10'},async (_bin,args)=>{
    await writeFile(`${args[args.indexOf('-output')+1]}.json`,raw);
    return {stdout:'+ ERROR: Host maximum execution time of 45 seconds reached\n+ Scan terminated: 0 errors and 1 items reported',stderr:'',code:0,error:''};
  });
  assert.equal(r.reportAvailable,true); assert.equal(r.raw,raw);
  assert.ok(r.error); assert.equal(parseAnalysisReport('nikto',r.raw).length,1);
});
test('Nikto FAIL con JSON y código cero sigue siendo una incidencia, nunca una vulnerabilidad', async () => {
  const raw=JSON.stringify([{vulnerabilities:[{id:'FAIL',msg:'Unable to connect',url:'/'}]}]);
  const r=await executeAnalysis({...defaultAnalysisQuery(),tool:'nikto',target:'192.0.2.10'},async (_bin,args)=>{
    await writeFile(`${args[args.indexOf('-output')+1]}.json`,raw);
    return {stdout:'+ [FAIL] Unable to connect to 192.0.2.10:443',stderr:'',code:0,error:''};
  });
  assert.equal(r.reportAvailable,true); assert.ok(r.error);
  assert.deepEqual(parseAnalysisReport('nikto',r.raw),[]);
});
test('Nikto vacío conserva consola como texto y no se toma por un reporte válido', async () => {
  const r=await executeAnalysis({...defaultAnalysisQuery(),tool:'nikto',target:'192.0.2.10'},async (_bin,args)=>{
    await writeFile(`${args[args.indexOf('-output')+1]}.json`,'');
    return {stdout:'+ Server: test-fixture',stderr:'',code:0,error:''};
  });
  assert.equal(r.reportAvailable,false); assert.match(r.error,/vacío/); assert.equal(r.raw,'+ Server: test-fixture');
});
test('Nikto solicita SIGINT y aplica SIGKILL si no cierra, manteniendo el límite y limpiando señales', async () => {
  const before=process.listenerCount('SIGHUP');
  const child=new EventEmitter(); child.stdout=new EventEmitter(); child.stderr=new EventEmitter();
  const signals=[];
  child.kill=signal=>{signals.push(signal);if(signal==='SIGKILL') queueMicrotask(()=>child.emit('close',null));};
  const r=await runTool('nikto',[],40,'/tmp',()=>child);
  assert.deepEqual(signals,['SIGINT','SIGKILL']); assert.match(r.error,/Tiempo agotado/);
  assert.equal(process.listenerCount('SIGHUP'),before);
});
function approved() {
  return approveScopePlan({ ...newScopePlan(), organization:'Laboratorio', objective:'Analizar servicios', assessor:'Operador', authorizer:'Propietario', authorizationReference:'LAB-001', includes:['192.0.2.0/24'], excludes:['192.0.2.99'], windowStart:'2026-10-02T11:00:00Z', windowEnd:'2026-10-02T14:00:00Z', contactName:'Coordinación', contactChannel:'Canal', incidentName:'Incidentes', incidentChannel:'Canal', sourceDescription:'Kali', allowedPorts:'80,443', analysisTools:{nikto:true,testssl:true} }, true, now);
}
test('Análisis existente funciona sin plan; pruebas activas exigen permiso específico, IP, puerto y ventana',()=> {
  const q = { ...defaultAnalysisQuery(), product:'Apache', target:'192.0.2.10', port:443, tool:'nikto' };
  assert.deepEqual(analysisQueryIssues(q,approved(),now),[]);
  for (const [query,plan] of [
    [q,undefined], [q,{...approved(),analysisTools:{nikto:false,testssl:false}}],
    [q,{...approved(),status:'paused'}], [{...q,target:'192.0.2.99'},approved()],
    [{...q,target:'lab.test'},approved()], [{...q,target:'192.0.2.0/24'},approved()],
    [{...q,port:22},approved()], [q,{...approved(),windowEnd:new Date(now+1000).toISOString()}],
  ]) assert.ok(analysisQueryIssues(query,plan,now).length);
  assert.deepEqual(analysisQueryIssues({...q,tool:'searchsploit'},undefined,now),[]);
});
test('Planes antiguos no reciben permisos activos; permisos inválidos no se importan',()=> {
  const old = approved(); delete old.analysisTools;
  assert.deepEqual(validateScopePlan(old).analysisTools,{nikto:false,testssl:false});
  assert.throws(()=>validateScopePlan({...old,analysisTools:{nikto:'yes',testssl:true}}),/Permisos/);
});
test('Resumen conserva procedencia y última observación sin reutilizar versiones de puertos cerrados',()=> {
  const row = (state,version) => ({address:'192.0.2.10', ports:[{port:443,protocol:'tcp',state,service:'https',product:'Apache',version}]});
  const p = {...project,lastRuns:[{id:'new',date:'2026-10-02T12:00:00Z',hosts:[row('closed','2.4.60')]},{id:'old',date:'2026-10-01T12:00:00Z',hosts:[row('open','2.4.50')]}]};
  assert.equal(analysisInventory(p).length,0);
  p.lastRuns[0].hosts[0].ports[0].state = 'open';
  const r=analysisInventory(p)[0]; assert.equal(r.observed.version,'2.4.60'); assert.equal(r.runId,'new');
  assert.deepEqual(toolRecommendations(r.observed).map(r=>r.tool),['searchsploit','cve','nikto','testssl']);
  assert.ok(!toolRecommendations({...r.observed,protocol:'udp'}).some(r=>r.tool==='nikto'));
});
test('Los cinco adaptadores interpretan reportes conservando CVE, severidad y condiciones como candidatas',()=> {
  const samples = [
    ['searchsploit',{RESULTS_EXPLOIT:[{Title:'Apache referencia',Codes:'CVE-2021-44228','EDB-ID':'123',Path:'/usr/share/exploitdb/exploits/example.txt'}]}],
    ['cve',[{id:'CVE-2021-44228',summary:'Condiciones y versión',cvss:10}]],
    ['nikto',{vulnerabilities:[{id:'1',url:'/path',msg:'Configuración expuesta'}]}],
    ['testssl',[{id:'SSLv3',finding:'Protocolo antiguo',severity:'HIGH',cve:'CVE-2014-3566'},{id:'TLS1.3',finding:'OK',severity:'OK'}]],
    ['trivy',{SchemaVersion:2,Results:[{Vulnerabilities:[{VulnerabilityID:'CVE-2021-44228',PkgName:'biblioteca',InstalledVersion:'1.0',FixedVersion:'2.0',Severity:'CRITICAL',Description:'Condiciones'}]}]}],
  ];
  for (const [tool,raw] of samples) {
    const findings=parseAnalysisReport(tool,JSON.stringify(raw)); assert.equal(findings.length,1);
    const d=appendAnalysis(undefined,{...evidence,tool,raw:JSON.stringify(raw)},findings);
    assert.equal(d.findings[0].status,'candidate'); assert.equal(d.findings[0].evidenceId,'e1');
  }
  assert.deepEqual(parseAnalysisReport('searchsploit','{"RESULTS_EXPLOIT":[]}'),[]);
  assert.throws(()=>parseAnalysisReport('testssl','[{}]'),/incompleta/);
  assert.throws(()=>parseAnalysisReport('cve','{"error":"unavailable"}'),/no reconocido/);
  assert.throws(()=>parseAnalysisReport('searchsploit','partial'),SyntaxError);
  assert.throws(()=>parseAnalysisReport('cve',JSON.stringify(Array.from({length:501},()=>({id:'CVE-2021-44228',summary:'test'})))),/supera 500/);
});
test('Persistencia conserva análisis, depura credenciales y rechaza referencias rotas, estados y confirmación sin evidencia',()=> {
  const data=appendAnalysis(emptyAnalysis(),{...evidence,raw:'password=secret-value'},[finding]);
  const w = {projects:[{...project,analysis:data}],selectedProjectId:'lab'};
  const imported=importWorkspace(exportWorkspace(w));
  assert.equal(imported.projects[0].analysis.findings[0].title,finding.title);
  assert.ok(!exportWorkspace(w).includes('secret-value'));
  for (const mutate of [
    d=>d.findings[0].evidenceId='missing', d=>d.findings[0].status='unverified',
    d=>d.findings[0].status='confirmed', d=>d.evidence.push(d.evidence[0]),
    d=>d.evidence[0].date='invalid', d=>d.findings[0].cves=['bad'],
  ]) {const copy=structuredClone(data);mutate(copy);assert.throws(()=>validateAnalysisData(copy));}
  assert.throws(()=>appendAnalysis({...data,evidence:Array.from({length:30},(_,i)=>({...evidence,id:`e${i}`}))},evidence,[]),/Límite/);
});
test('Datos de entrada son argumentos, no shell; Trivy evita búsquedas y actualizaciones remotas',()=> {
  const q={...defaultAnalysisQuery(),product:'Apache; $(not-executed)',version:'2.4'};
  const validated=validateAnalysisQuery(q); const [bin,args]=toolArguments(validated,'/tmp/report');
  assert.equal(bin,'searchsploit');assert.equal(args[1],q.product);
  assert.throws(()=>validateAnalysisQuery({...q,product:'--update'}),/inválidos/);
  assert.throws(()=>validateAnalysisQuery({...q,cve:'CVE-invalid'}),/inválido/);
  assert.throws(()=>validateAnalysisQuery({...q,tool:'trivy',path:'relative'}),/absoluta/);
  assert.throws(()=>validateAnalysisQuery({...q,tool:'cve'}),/proveedor/);
  const trivy={...defaultAnalysisQuery(),tool:'trivy',path:'/opt/evidence'};
  const command=toolArguments(trivy,'/tmp/report')[1];
  for(const flag of ['--offline-scan','--skip-db-update','--skip-java-db-update','--skip-version-check']) assert.ok(command.includes(flag));
  assert.equal(command.at(-2),'--');assert.equal(command.at(-1),trivy.path);
  assert.match(analysisCommand(trivy),/skip-db-update/);
  assert.ok(toolArguments({...q,tool:'nikto',target:'host.test'},'/tmp/report')[1].includes('https://host.test:443'));
});
test('Runner conserva UTF-8, usa spawn sin shell y limpia timeout y señales',async()=> {
  const before=process.listenerCount('SIGHUP');
  const fake = new EventEmitter();fake.stdout=new EventEmitter();fake.stderr=new EventEmitter();fake.kill=()=>{};
  const resultPromise=runTool('searchsploit',['-j','Apache'],1000,'/tmp',(_bin,_args,options)=>{assert.equal(options.shell,false);assert.equal(options.env.TRIVY_SERVER,undefined);return fake;});
  const bytes=Buffer.from('evidencia ñ');fake.stdout.emit('data',bytes.subarray(0,bytes.length-1));fake.stdout.emit('data',bytes.subarray(bytes.length-1));fake.emit('close',0);
  assert.equal((await resultPromise).stdout,'evidencia ñ');assert.equal(process.listenerCount('SIGHUP'),before);
  const timeoutFake=new EventEmitter();timeoutFake.stdout=new EventEmitter();timeoutFake.stderr=new EventEmitter();let killed=false;
  timeoutFake.kill=()=>{killed=true;queueMicrotask(()=>timeoutFake.emit('close',null));};
  const timed=await runTool('nikto',[],5,'/tmp',()=>timeoutFake);assert.equal(killed,true);assert.match(timed.error,/Tiempo agotado/);assert.equal(timed.code,null);
  const missing=new EventEmitter();missing.stdout=new EventEmitter();missing.stderr=new EventEmitter();missing.kill=()=>{};
  const p=runTool('missing',[],1000,'/tmp',()=>missing);missing.emit('error',Object.assign(new Error('missing'),{code:'ENOENT'}));assert.match((await p).error,/no está instalado/);
});
test('Incidencias de análisis no alteran checklist de reconocimiento o enumeración',()=> {
  const failure=makeFailure({phase:'analysis',stage:'Ejecutar herramienta',source:'nikto',target:'192.0.2.10',error:'falló'});
  const p={...project,plan:approved(),failures:[failure]};
  assert.deepEqual(projectCheckAttempts(p),[]);
  const pending={...failure,projectId:project.id};
  assert.ok(!projectChecklist(p,'recon',{pending:[pending]}).some(r=>r.status==='running'));
});
