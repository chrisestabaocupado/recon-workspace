// Optional live check of the public API, without contacting any assessment target.
import assert from 'node:assert/strict';
import { setTimeout } from 'node:timers/promises';
import test from 'node:test';
import { defaultAnalysisQuery, parseAnalysisReport } from '../src/lib/analysis.ts';
import { executeAnalysis } from '../src/server/remote-analysis.mjs';

test('NVD real devuelve CVE y filtra Apache HTTP Server 2.4.49 por CPE', async () => {
  const q={...defaultAnalysisQuery(),tool:'nvd',timeoutSeconds:60,cve:'CVE-2021-41773'};
  const byId=await executeAnalysis(q);
  assert.equal(parseAnalysisReport('nvd',byId.raw)[0].title,q.cve);
  await setTimeout(6000);
  const byCpe=await executeAnalysis({...q,cve:'',cpe:'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'});
  assert.ok(parseAnalysisReport('nvd',byCpe.raw).some((f)=>f.cves.includes(q.cve)));
  console.log(byCpe.database);
});
