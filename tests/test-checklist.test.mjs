import assert from 'node:assert/strict';
import test from 'node:test';
import { appendCheckHistory, CHECK_HISTORY_LIMIT, checklistMarkdown, evidenceCheck, projectChecklist, runCheck, validateCheckHistory } from '../src/lib/test-checklist.ts';
import { exportWorkspace, importWorkspace, validateWorkspace } from '../src/lib/storage.ts';
import { saveExecutionResult } from '../src/lib/execution-history.ts';
import { saveReconResult, deleteReconEvidence } from '../src/lib/recon-project.ts';
import { makeFailure } from '../src/lib/operation-history.ts';
import { approveScopePlan, newScopePlan } from '../src/lib/scope.ts';

const now = Date.parse('2026-10-02T15:00:00Z');
const domain = 'scope-lab.net';
const date = (minutes = 0) => new Date(now + minutes * 60000).toISOString();
function plan() { return approveScopePlan({ ...newScopePlan(), passiveRecon: true, organization: 'Lab', objective: 'Synthetic', assessor: 'Operator', authorizer: 'Owner', authorizationReference: 'SIMULATED', includes: [domain], excludes: [], windowStart: '2026-10-02T11:00:00Z', windowEnd: '2026-10-02T18:00:00Z', contactName: 'Contact', contactChannel: 'Test', incidentName: 'Contact', incidentChannel: 'Test', sourceDescription: 'Synthetic' }, true, now); }
const project = () => ({ id: 'a', name: 'Lab', scope: '', createdAt: date(), targets: [], executions: 0, plan: plan() });
const workspace = (p = project()) => ({ projects: [p], selectedProjectId: 'a' });
const evidence = (extra = {}) => ({ id: 'e1', source: 'crtsh', query: domain, sourceUrl: 'https://crt.sh/', retrievedAt: date(2), scopeRevision: 1, facts: [{ label: 'Certificados recibidos', value: '29' }], warnings: [], notes: '', ...extra });
const failure = (extra = {}) => makeFailure({ id: 'f1', phase: 'recon', stage: 'Consultar fuente', source: 'crtsh', target: domain, date: date(1), scopeRevision: 1, error: 'HTTP 502', ...extra });
const recon = (e) => ({ version: 1, evidence: [e], assets: [] });

test('El checklist distingue una consulta recuperada de sus errores anteriores y muestra pendientes por dominio exacto', () => {
  const p = { ...project(), failures: [failure()], recon: recon(evidence()) };
  const rows = projectChecklist(p, 'recon');
  assert.equal(rows.length, 4);
  const crt = rows.find((r) => r.kind === 'crtsh');
  assert.equal(crt.status, 'data');
  assert.equal(crt.recovered, true);
  assert.deepEqual(crt.attempts.map((a) => a.status), ['data', 'failed']);
  assert.equal(rows.find((r) => r.kind === 'rdap').status, 'pending');
  assert.ok(rows.every((r) => r.target === domain));
  assert.ok(!rows.some((r) => r.target === `parent.${domain}`));
});

test('Un fallo posterior reemplaza el estado del checklist aunque se conserve evidencia de un intento anterior', () => {
  const p = { ...project(), failures: [failure({ date: date(3) })], recon: recon(evidence()) };
  const row = projectChecklist(p, 'recon').find((r) => r.kind === 'crtsh');
  assert.equal(row.status, 'failed');
  assert.equal(row.recovered, false);
  assert.equal(row.attempts.length, 2);
});

test('El checklist de IP individuales solo propone DNS y TLS y reconoce los resultados PTR', () => {
  const address = '172.16.10.24';
  const p = { ...project(), plan: { ...plan(), includes: [address, '2001:db8::24', '172.16.20.0/24'] } };
  const rows = projectChecklist(p, 'recon');
  assert.equal(rows.length, 4);
  assert.ok(rows.every((row) => ['dns', 'tls'].includes(row.kind)));
  assert.ok(rows.every((row) => !row.target.includes('/')));
  const ptr = evidence({ source: 'dns', query: address, sourceUrl: '', facts: [{ label: 'IP consultada', value: address }, { label: 'PTR', value: 'glpi.internal' }] });
  assert.equal(evidenceCheck(ptr).status, 'data');
  assert.equal(evidenceCheck({ ...ptr, facts: [{ label: 'PTR', value: 'Sin registros PTR (ENOTFOUND)' }] }).status, 'empty');
  assert.equal(projectChecklist({ ...p, recon: recon(ptr) }, 'recon').find((row) => row.kind === 'dns' && row.target === address).status, 'data');
  assert.equal(evidenceCheck(evidence({ source: 'tls', query: '2001:db8::24', sourceUrl: 'https://[2001:db8::24]:8443/' })).target, '[2001:db8::24]:8443');
});

test('DNS parcial y sin registros tienen estados distintos de error; TLS no validado queda parcial', () => {
  const dns = evidence({ source: 'dns', sourceUrl: '', facts: [{ label: 'A', value: '192.0.2.10' }, { label: 'SOA', value: 'Consulta no disponible (EBADRESP)' }] });
  assert.equal(evidenceCheck(dns).status, 'partial');
  assert.equal(evidenceCheck({ ...dns, facts: [{ label: 'A', value: 'Sin registros (ENODATA)' }] }).status, 'empty');
  assert.equal(evidenceCheck(evidence({ facts: [{ label: 'Certificados recibidos', value: '0' }] })).status, 'empty');
  assert.equal(evidenceCheck(evidence({ source: 'tls', sourceUrl: `https://${domain}:8443/`, warnings: ['La cadena TLS no fue validada: SELF_SIGNED_CERT.'] })).status, 'partial');
  assert.equal(evidenceCheck(evidence({ source: 'tls', sourceUrl: `https://${domain}:8443/` })).target, `${domain}:8443`);
  assert.equal(evidenceCheck(evidence({ source: 'manual' })).status, 'provided');
  assert.equal(evidenceCheck(evidence({ warnings: ['JSON aportado por el operador: procedencia declarada.'] })).status, 'provided');
});

test('Cambiar la revisión deja pruebas antiguas pendientes en el plan actual sin perder su historial', () => {
  const p = { ...project(), plan: { ...plan(), revision: 2 }, recon: recon(evidence()), failures: [failure()] };
  assert.ok(projectChecklist(p, 'recon').every((r) => r.status === 'pending'));
  const old = projectChecklist(p, 'recon', { includePrevious: true }).find((r) => r.kind === 'crtsh');
  assert.equal(old.status, 'data');
  assert.equal(old.attempts[0].scopeRevision, 1);
  const noRevision = { ...project(), recon: recon(evidence({ scopeRevision: undefined })) };
  assert.equal(projectChecklist(noRevision, 'recon').find((r) => r.kind === 'crtsh').status, 'pending');
});

test('La consulta pendiente y Nmap activo muestran En curso sin inventar un resultado', () => {
  const p = { ...project(), recon: recon(evidence()) };
  const pending = [{ ...failure({ id: 'p1', date: date(3) }), projectId: 'a' }];
  assert.equal(projectChecklist(p, 'recon', { pending }).find((r) => r.kind === 'crtsh').status, 'running');
  const execution = { id: 'j1', projectId: 'a', state: 'running', targets: [domain], command: `nmap ${domain}`, scopeRevision: 1, startedAt: date() };
  assert.equal(projectChecklist(p, 'enumeration', { execution })[0].status, 'running');
  assert.equal(projectChecklist(p, 'enumeration', { execution: { ...execution, projectId: 'another' } })[0].status, 'pending');
});

test('El historial Nmap sobrevive a la retención de diez reportes, sin duplicar finales ni clasificar cancelación como fallo', () => {
  let data = workspace();
  for (let i = 0; i < 12; i++) {
    const snapshot = { id: `j${i}`, projectId: 'a', command: `nmap ${domain}`, targets: [domain], mode: 'ssh', startedAt: date(i), scopeRevision: 1 };
    const result = { state: 'completed', date: date(i), logs: 'Nmap done: 1 IP address (0 hosts up) scanned', truncated: false };
    data = saveExecutionResult(data, snapshot, result);
    data = saveExecutionResult(data, snapshot, result);
  }
  assert.equal(data.projects[0].lastRuns.length, 10);
  assert.equal(data.projects[0].checkHistory.length, 12);
  assert.equal(projectChecklist(data.projects[0], 'enumeration')[0].attempts.length, 12);
  const imported = importWorkspace(exportWorkspace(data));
  assert.equal(imported.projects[0].checkHistory.length, 12);
  assert.equal(runCheck({ id: 'c', state: 'cancelled', command: 'nmap', date: date(), excerpt: '' }).status, 'cancelled');
  assert.equal(runCheck({ id: 'd', state: 'completed', command: 'nmap --version', date: date(), excerpt: 'Nmap version' }).status, 'completed');
  assert.equal(runCheck({ id: 'p', state: 'completed', command: 'nmap', date: date(), excerpt: '', reportError: 'XML incompleto' }).status, 'partial');
});

test('Borrar evidencia no borra que la prueba se ejecutó; el resultado permanece separado del inventario', () => {
  const e = evidence();
  const result = { ...e, assets: [domain] };
  let data = saveReconResult(workspace(), 'a', result, '', () => 'generated');
  data = deleteReconEvidence(data, 'a', 'generated');
  assert.equal(data.projects[0].recon.evidence.length, 0);
  assert.equal(data.projects[0].checkHistory.length, 1);
  assert.equal(projectChecklist(data.projects[0], 'recon').find((r) => r.kind === 'crtsh').status, 'data');
  assert.match(checklistMarkdown(data.projects[0], 'recon'), /Con datos/);
});

test('La migración reconstruye registros guardados, valida el nuevo historial y elimina secretos al exportar', () => {
  const legacy = validateWorkspace(workspace({ ...project(), recon: recon(evidence()) }));
  assert.equal(legacy.projects[0].checkHistory.length, 1);
  const attempt = evidenceCheck(evidence());
  const dirty = { ...attempt, command: 'nmap --script-args "password=VERYSECRET" scope-lab.net', detail: 'password=VERYSECRET', kaliToken: 'REMOVE' };
  const clean = validateCheckHistory([dirty])[0];
  assert.ok(!JSON.stringify(clean).includes('VERYSECRET'));
  assert.equal(clean.kaliToken, undefined);
  assert.throws(() => validateCheckHistory([{ ...attempt, kind: 'unknown' }]));
  assert.throws(() => validateCheckHistory([{ ...attempt, status: 'vulnerable' }]));
  assert.throws(() => validateCheckHistory([{ ...attempt, phase: 'enumeration' }]));
  assert.throws(() => validateCheckHistory([attempt, attempt]));
  let history = [];
  for (let i = 0; i <= CHECK_HISTORY_LIMIT; i++) history = appendCheckHistory(history, { ...attempt, id: `id${i}` });
  assert.equal(history.length, CHECK_HISTORY_LIMIT);
});
