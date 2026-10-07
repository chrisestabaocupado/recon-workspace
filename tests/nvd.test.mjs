import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { nvdCpe, nvdUrl } from '../src/lib/nvd.mjs';
import { analysisInventory, appendAnalysis, defaultAnalysisQuery, parseAnalysisReport, serviceAnalysisQuery, validateAnalysisQuery } from '../src/lib/analysis.ts';
import { readNmapReport } from '../src/lib/results.ts';
import { exportWorkspace, importWorkspace } from '../src/lib/storage.ts';
import { cveResponse, executeAnalysis } from '../src/server/remote-analysis.mjs';

const cpe = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
const query = {...defaultAnalysisQuery(),tool:'nvd',product:'Apache httpd',version:'2.4.49',cpe};
const response = {totalResults:1,vulnerabilities:[{cve:{id:'CVE-2021-41773',published:'2021-10-05',lastModified:'2026-01-01',vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'Path traversal in Apache HTTP Server'}],metrics:{cvssMetricV31:[{type:'Primary',cvssData:{baseScore:7.5}}]},configurations:[{nodes:[{cpeMatch:[{vulnerable:true,criteria:cpe,versionEndExcluding:'2.4.50'}]}]}]}}]};

test('NVD prioriza CVE y CPE; el texto no finge filtrar por versión ni envía IP',()=>{
  const q=validateAnalysisQuery(query);
  let url=new URL(nvdUrl({...q,target:'192.0.2.10'}));
  assert.equal(url.origin,'https://services.nvd.nist.gov');
  assert.equal(url.searchParams.get('cpeName'),cpe);
  assert.ok(url.searchParams.has('isVulnerable'));
  assert.ok(!url.toString().includes('192.0.2.10'));
  url=new URL(nvdUrl({...q,cve:'CVE-2021-41773'}));
  assert.equal(url.searchParams.get('cveId'),'CVE-2021-41773');assert.ok(!url.searchParams.has('cpeName'));
  url=new URL(nvdUrl({...q,cpe:''}));
  assert.equal(url.searchParams.get('keywordSearch'),'Apache httpd');assert.ok(!url.toString().includes('2.4.49'));
  assert.throws(()=>validateAnalysisQuery({...query,cpe:'',product:''}),/producto/);
  assert.equal(validateAnalysisQuery({...query,cpe:'',product:'',cve:'cve-2021-41773'}).cve,'CVE-2021-41773');
});

test('CPE simple de Nmap se convierte; versiones comodín y formatos ambiguos exigen revisión',()=>{
  assert.equal(nvdCpe('cpe:/a:apache:http_server:2.4.49'),cpe);
  for(const value of ['cpe:/a:apache:http_server','cpe:/a:apache:http_server:2%2e4','cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*','https://evil.test/']) assert.throws(()=>nvdCpe(value));
  assert.equal(nvdCpe(cpe),cpe);
});

test('NVD interpreta CVSS, fechas y rangos; conserva JSON y hallazgos como candidatas',()=>{
  const findings=parseAnalysisReport('nvd',JSON.stringify(response));
  assert.equal(findings[0].severity,'CVSS 7.5');assert.match(findings[0].description,/versionEndExcluding=2.4.50/);
  assert.match(findings[0].description,/https:\/\/nvd.nist.gov\/vuln\/detail\/CVE-2021-41773/);
  const evidence={id:'nvd1',tool:'nvd',target:'192.0.2.10',port:80,query:nvdUrl(query),date:new Date().toISOString(),raw:JSON.stringify(response),warnings:[],error:''};
  const data=appendAnalysis(undefined,evidence,findings);
  assert.equal(data.findings[0].status,'candidate');assert.equal(data.findings[0].port,80);
  assert.deepEqual(parseAnalysisReport('nvd',JSON.stringify({totalResults:0,vulnerabilities:[]})),[]);
  assert.throws(()=>parseAnalysisReport('nvd','{"error":"unavailable"}'),/NVD/);
  assert.throws(()=>parseAnalysisReport('nvd',JSON.stringify({totalResults:1,vulnerabilities:[{cve:{id:'bad',descriptions:[]}}]})),/incompleta/);
});

test('Runner NVD indica truncamiento, evita shell y conserva errores HTTP y límites de tamaño',async()=>{
  const runner=()=>{throw new Error('No debe ejecutar binarios');};
  const result=await executeAnalysis(query,runner,undefined,async(url,options)=>{
    assert.equal(new URL(url).searchParams.get('cpeName'),cpe);assert.equal(options.redirect,'error');assert.ok(options.signal);
    return Response.json({...response,totalResults:150});
  });
  assert.match(result.database,/no es una lista completa/);assert.match(result.database,/Coincidencia de CPE/);
  const text=await executeAnalysis({...query,cpe:''},runner,undefined,async()=>Response.json(response));
  assert.match(text.database,/NO se filtra/);
  for(const status of [403,429,503]) await assert.rejects(()=>executeAnalysis(query,runner,undefined,async()=>new Response('',{status})),new RegExp(`HTTP ${status}`));
  await assert.rejects(()=>cveResponse(nvdUrl(query),5000,async()=>new Response('a'.repeat(2*1024*1024+1))),/2 MB/);
});

test('XML conserva CPE a través de exportación y prepara una consulta del servicio observado',()=>{
  const hosts=readNmapReport('<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port portid="80" protocol="tcp"><state state="open"/><service name="http" product="Apache httpd" version="2.4.49"><cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port></ports></host></nmaprun>');
  const project={id:'lab',name:'Lab',scope:'192.0.2.10',createdAt:new Date().toISOString(),targets:[],executions:1,lastRuns:[{id:'run1',command:'nmap',state:'completed',date:new Date().toISOString(),excerpt:'',hosts}]};
  const imported=importWorkspace(exportWorkspace({projects:[project],selectedProjectId:'lab'}));
  const row=analysisInventory(imported.projects[0])[0];
  assert.deepEqual(row.observed.cpes,['cpe:/a:apache:http_server:2.4.49']);
  const q=serviceAnalysisQuery(row,'nvd');assert.equal(q.cpe,cpe);assert.equal(q.target,'192.0.2.10');assert.equal(q.version,'2.4.49');
});

test('El programa SSH incorpora NVD y su parser CPE sin depender de archivos de la app',async()=>{
  const source=await readFile(new URL('../src/server/remote-analysis.mjs',import.meta.url),'utf8');
  const web=await readFile(new URL('../src/lib/web-target.mjs',import.meta.url),'utf8');
  const nvd=await readFile(new URL('../src/lib/nvd.mjs',import.meta.url),'utf8');
  const program=source.replace('import { parseNiktoTarget } from "../lib/web-target.mjs";',web.replace('export function parseNiktoTarget','function parseNiktoTarget')).replace('import { nvdUrl } from "../lib/nvd.mjs";',nvd.replaceAll('export function','function'));
  const result=spawnSync(process.execPath,['--input-type=module','-e',program],{input:JSON.stringify({operation:'run',query:{...query,cpe:'invalid'}}),encoding:'utf8',timeout:5000});
  assert.equal(result.status,1);assert.match(result.stderr,/CPE 2.3/);assert.ok(!result.stderr.includes('ERR_MODULE_NOT_FOUND'));
});


