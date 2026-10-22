import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { buildProjectReport, mappingInventory, reportMarkdown, reportFilename } from '../src/lib/report.ts';
import { exportWorkspace, importWorkspace, validateWorkspace } from '../src/lib/storage.ts';
import { newScopePlan } from '../src/lib/scope.ts';
import { emptyRecon } from '../src/lib/recon.ts';
import { makeFailure } from '../src/lib/operation-history.ts';

const date='2026-10-22T12:00:00Z';
const project=()=>({id:'p1',name:'Laboratorio',scope:'Reconocimiento autorizado',createdAt:date,targets:[],executions:0});
const run=(id,when,ports=[],extra={})=>({id,date:when,state:'completed',command:'nmap -sT 192.0.2.10',excerpt:'',hosts:[{address:'192.0.2.10',status:'up',ports}],...extra});
const port=(number,state='open')=>({port:number,protocol:'tcp',state,service:'http',product:'Servidor',version:'1.2'});
const section=(report,title)=>report.sections.find(s=>s.title===title);

test('El informe funciona sin datos y no inventa resultados ni autorización',()=>{
  const p=project();
  const report=buildProjectReport(p,date);
  assert.deepEqual(report.summary,{assets:0,hosts:0,openPorts:0,evidence:0});
  assert.match(reportMarkdown(report),/Sin hosts observados/);
  assert.match(reportMarkdown(report),/Sin plan registrado/);
  assert.match(reportMarkdown(report),/No evalúa vulnerabilidades/);
  assert.ok(section(report,'Estado de recopilación · Mapeo').rows.some(r=>r.includes('Pendiente')));
  assert.equal(p.lastRuns,undefined);
});

test('El mapa combina observaciones en orden cronológico sin duplicar endpoints ni ocultar cierres',()=>{
  const old=run('old','2026-10-20T12:00:00Z',[port(80),port(443)],{scopeRevision:1});
  const latest=run('new',date,[port(80,'closed'),{...port(53,'open|filtered'),protocol:'udp'}],{state:'timed_out',scopeRevision:2});
  const p={...project(),executions:3,lastRuns:[latest,run('empty','2026-10-21T12:00:00Z'),old]};
  const snapshot=structuredClone(p);
  const mapped=mappingInventory(p);
  assert.equal(mapped.length,1);
  assert.equal(mapped[0].ports.length,3);
  assert.equal(mapped[0].ports.find(p=>p.observed.port===80).observed.state,'closed');
  assert.equal(mapped[0].ports.find(p=>p.observed.port===443).run.id,'old');
  const report=buildProjectReport(p,date);
  assert.equal(report.summary.openPorts,1);
  const md=reportMarkdown(report);
  for(const expected of ['Tiempo agotado','r1','r2','old','new']) {
    assert.ok(md.includes(expected),expected);
  }
  assert.deepEqual(p,snapshot);
  const tied=mappingInventory({...project(),lastRuns:[run('new',date,[port(80,'closed')]),run('old',date,[port(80)])]});
  assert.equal(tied[0].ports[0].observed.state,'closed');
});

test('Incluye alcance, evidencias, incidencias propias y procedencia, sin datos de otros proyectos',()=>{
  const p={...project(),plan:{...newScopePlan(),organization:'Laboratorio',revision:2,includes:['192.0.2.0/24'],excludes:['192.0.2.99']},targets:[{id:'t',value:'192.0.2.10',note:'Servidor'}],recon:{...emptyRecon(),assets:[{id:'a',value:'192.0.2.10',status:'reviewed',evidenceIds:['e1'],note:'Revisado',updatedAt:date},{id:'d',value:'192.0.2.99',status:'discarded',evidenceIds:['e1'],note:'Excluir',updatedAt:date}],evidence:[{id:'e1',source:'manual',query:'Inventario interno',sourceUrl:'',retrievedAt:date,scopeRevision:1,facts:[{label:'Nombre',value:'Servidor interno'}],warnings:['Pendiente contrastar'],notes:'Aportado por operaciones'}]},failures:[makeFailure({id:'f1',date,phase:'recon',stage:'Consulta',error:'Sin conexión'})]};
  const report=buildProjectReport(p,date);
  assert.equal(report.summary.assets,1);
  assert.equal(report.summary.evidence,1);
  const md=reportMarkdown(report);
  for(const expected of ['Servidor interno','Pendiente contrastar','Sin conexión','r1','r2','192.0.2.99','Exclusiones','Referencia escrita']) assert.ok(md.includes(expected),expected);
  assert.ok(section(report,'Activos descubiertos').rows[1].includes('Descartado'));
});

test('La vista y Markdown comparten modelo, depuran secretos y neutralizan HTML y tablas inyectadas',()=>{
  const p={...project(),name:'<script>alert(1)</script> | [nombre]',scope:'token=SECRET\n-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATEVALUE\n-----END OPENSSH PRIVATE KEY-----',lastRuns:[run('r',date,[],{command:'nmap --script-args "password=COMMANDSECRET" 192.0.2.10'})]};
  const report=buildProjectReport(p,date);
  const md=reportMarkdown(report);
  for(const secret of ['SECRET','PRIVATEVALUE','COMMANDSECRET']) assert.ok(!JSON.stringify(report).includes(secret));
  assert.ok(!md.includes('<script>'));
  assert.match(md,/&lt;script&gt;/);
  assert.match(md,/\\\|/);
  assert.ok(!reportFilename('../unsafe/name').includes('/'));
  assert.equal(reportFilename(''),'informe-proyecto.md');
});

test('La migración retira análisis sin perder proyectos, evidencias, mapeo ni asociación de pendientes',()=>{
  const retired={id:'old',phase:'analysis',projectId:'old-project'};
  const current={...makeFailure({id:'pending',date,phase:'recon',stage:'Consulta',error:'Pendiente'}),projectId:'p1'};
  const p={...project(),analysis:{legacy:true},plan:{...newScopePlan(),analysisTools:{nikto:true,testssl:true}},recon:emptyRecon(),lastRuns:[run('scan',date,[port(80)])],failures:[retired,makeFailure({id:'kept',date,phase:'enumeration',stage:'Escaneo',error:'Timeout'})]};
  const migrated=validateWorkspace({projects:[p],selectedProjectId:'p1',pendingOperations:[retired,current],failures:[retired]});
  assert.equal(migrated.projects[0].analysis,undefined);
  assert.equal(migrated.projects[0].plan.analysisTools,undefined);
  assert.deepEqual(migrated.projects[0].recon,emptyRecon());
  assert.equal(migrated.projects[0].lastRuns[0].hosts[0].ports[0].port,80);
  assert.equal(migrated.projects[0].failures[0].id,'kept');
  assert.deepEqual(migrated.failures,[]);
  assert.equal(migrated.pendingOperations[0].projectId,'p1');
  assert.deepEqual(importWorkspace(exportWorkspace(migrated)),migrated);
  assert.throws(()=>makeFailure({phase:'analysis',stage:'Retirado',error:'No debe registrarse'}),/Fase/);
});

test('Las actividades en curso aparecen solo en el proyecto al que pertenecen',()=>{
  const p={...project(),plan:newScopePlan()};
  const live={execution:{id:'active',projectId:'p1',command:'nmap 192.0.2.10',targets:['192.0.2.10'],state:'running',startedAt:date,scopeRevision:1},pending:[{id:'pending',projectId:'other',phase:'recon',source:'dns',target:'other.net',date}]};
  const md=reportMarkdown(buildProjectReport(p,date,live));
  assert.match(md,/En curso/);
  assert.ok(!md.includes('other.net'));
  assert.equal(buildProjectReport(p,date,live).summary.hosts,0);
});

test('Las rutas y navegación retiradas no reaparecen y PDF usa un documento aislado de la interfaz',async()=>{
  const routes=await readFile(new URL('../src/routeTree.gen.ts',import.meta.url),'utf8');
  const nav=await readFile(new URL('../src/components/PhaseSidebar.tsx',import.meta.url),'utf8');
  for(const text of [routes,nav]) for(const route of ['/analisis','/explotacion','/post-explotacion']) assert.ok(!text.includes(route));
  assert.ok(nav.includes('Informes'));
  const ui=await readFile(new URL('../src/components/reports/ReportWorkspace.tsx',import.meta.url),'utf8');
  const css=await readFile(new URL('../src/styles.css',import.meta.url),'utf8');
  assert.match(ui,/createPortal/);
  assert.match(ui,/window.print\(\)/);
  assert.match(css,/body:has\(\.report-print-root\) > :not\(\.report-print-root\)/);
});
