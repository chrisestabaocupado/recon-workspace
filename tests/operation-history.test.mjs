import assert from 'node:assert/strict';
import test from 'node:test';
import { appendFailure, FAILURE_LIMIT, failuresMarkdown, makeFailure, recoverPendingOperations, validateFailures } from '../src/lib/operation-history.ts';
import { exportWorkspace, importWorkspace, readWorkspaceResult, writeWorkspace } from '../src/lib/storage.ts';
import { saveExecutionResult } from '../src/lib/execution-history.ts';
import { reconMarkdown } from '../src/lib/recon-project.ts';
import { parseDnsResult, parseTlsResult } from '../src/lib/recon.ts';

const date = '2026-10-02T15:00:00Z';
const project = (id) => ({ id, name: `Proyecto ${id}`, scope: '', createdAt: date, targets: [], executions: 0 });
const workspace = () => ({ projects: [project('a'), project('b')], selectedProjectId: 'b' });
const failure = (extra = {}) => makeFailure({ phase: 'recon', stage: 'Consultar fuente', source: 'crtsh', target: 'scope-lab.net', error: 'HTTP 502', date, scopeRevision: 8, ...extra });

test('Los fallos sobreviven recarga, exportación e importación sin depender del proyecto seleccionado', () => {
  const memory = new Map();
  globalThis.window = { localStorage: { getItem: (k) => memory.get(k) ?? null, setItem: (k, v) => memory.set(k, v) } };
  const original = appendFailure(workspace(), 'a', failure());
  assert.equal(original.projects[1].failures, undefined);
  assert.equal(writeWorkspace(original).ok, true);
  const restored = readWorkspaceResult().data;
  assert.equal(restored.projects[0].failures[0].scopeRevision, 8);
  assert.deepEqual(importWorkspace(exportWorkspace(restored)), restored);
  assert.equal(restored.projects[0].executions, 0);
  assert.equal(restored.projects[0].recon, undefined);
});

test('Cada intento tiene su ID; solo el seguimiento con ID estable agrupa apariciones', () => {
  let data = appendFailure(workspace(), 'a', failure({ id: 'job:poll' }));
  data = appendFailure(data, 'a', failure({ id: 'job:poll', date: '2026-10-02T15:01:00Z', error: 'Conexión cerrada' }));
  assert.equal(data.projects[0].failures.length, 1);
  assert.equal(data.projects[0].failures[0].occurrences, 2);
  assert.equal(data.projects[0].failures[0].date, date);
  assert.equal(data.projects[0].failures[0].lastAt, '2026-10-02T15:01:00Z');
  assert.equal(data.projects[0].failures[0].error, 'Conexión cerrada');
  data = appendFailure(appendFailure(data, 'a', failure()), 'a', failure());
  assert.equal(data.projects[0].failures.length, 3);
  data = appendFailure(data, 'removed-project', failure());
  assert.equal(data.failures.length, 1);
});

test('El registro elimina secretos, claves y campos ajenos al importar y al copiar', () => {
  const entry = failure({ command: 'nmap --script-args "value=VERYSECRET" scope-lab.net', error: 'Falló VERYSECRET token=abc https://user:pass@example.com\n-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATEVALUE\n-----END OPENSSH PRIVATE KEY-----', passphrase: 'UNWANTED', kaliToken: 'UNWANTED' });
  const copied = failuresMarkdown([entry]);
  for (const secret of ['VERYSECRET', 'PRIVATEVALUE', 'token=abc', 'user:pass', 'UNWANTED']) assert.ok(!copied.includes(secret), secret);
  assert.equal(entry.passphrase, undefined);
  assert.equal(entry.kaliToken, undefined);
  assert.throws(() => validateFailures([{ ...entry, phase: 'invalid' }]));
  assert.throws(() => validateFailures([{ ...entry, date: 'invalid' }]));
  assert.throws(() => validateFailures([{ ...entry, occurrences: 0 }]));
  assert.throws(() => validateFailures([entry, entry]));
});

test('Nmap guarda timeout, fallo, resultado desconocido y errores de reporte una sola vez', () => {
  const snapshot = { id: 'job1', projectId: 'a', command: 'nmap scope-lab.net', targets: ['scope-lab.net'], mode: 'ssh', startedAt: date, scopeRevision: 8 };
  for (const state of ['failed', 'timed_out', 'unknown', 'interrupted']) {
    const result = { state, date, logs: '', truncated: false, error: `Estado ${state}` };
    let data = saveExecutionResult(workspace(), snapshot, result);
    data = saveExecutionResult(data, snapshot, result);
    assert.equal(data.projects[0].failures.length, 1);
    assert.equal(data.projects[0].failures[0].jobId, 'job1');
    assert.equal(data.projects[0].failures[0].occurrences, 1);
  }
  const cancelled = saveExecutionResult(workspace(), snapshot, { state: 'cancelled', date, logs: '', truncated: false });
  assert.equal(cancelled.projects[0].failures, undefined);
  const broken = saveExecutionResult(workspace(), snapshot, { state: 'completed', date, logs: '', xml: '<nmaprun><host>', truncated: false });
  assert.equal(broken.projects[0].failures[0].stage, 'Interpretar reporte');
});

test('Copiar todo e Informe Markdown incluyen fallos aunque no existan evidencias exitosas', () => {
  const p = appendFailure(workspace(), 'a', failure()).projects[0];
  assert.match(reconMarkdown(p), /HTTP 502/);
  assert.match(reconMarkdown(p, 'evidence'), /HTTP 502/);
  assert.doesNotMatch(reconMarkdown(p, 'assets'), /HTTP 502/);
  assert.doesNotMatch(reconMarkdown({ ...p, failures: [failure({ phase: 'enumeration' })] }), /HTTP 502/);
  assert.deepEqual(importWorkspace(exportWorkspace(workspace())).projects[0].failures, []);
});

test('Los errores parciales DNS y TLS son estructurados sin clasificar ausencia DNS como fallo', () => {
  const rows = ['A','AAAA','CNAME','MX','NS','TXT','SOA'].map((type) => ({ type, values: [], error: type === 'SOA' ? 'EBADRESP' : 'ENODATA' }));
  const result = parseDnsResult({ rows, resolvers: ['192.0.2.53'] }, 'scope-lab.net');
  assert.deepEqual(result.issues, [{ stage: 'DNS SOA', error: 'EBADRESP' }]);
  const cert = parseTlsResult({ address: '192.0.2.10', authorized: false, authorizationError: 'SELF_SIGNED_CERT', hostnameError: '', san: '', subject: 'scope-lab.net', issuer: 'Lab', validFrom: '', validTo: '', fingerprint: '', protocol: 'TLSv1.3' }, 'scope-lab.net', '192.0.2.10');
  assert.deepEqual(cert.issues, [{ stage: 'Validar cadena TLS', error: 'SELF_SIGNED_CERT' }]);
});

test('Una consulta sin respuesta guardada se recupera como resultado sin confirmar, una sola vez', () => {
  const pending = { ...failure({ id: 'pending1' }), projectId: 'a' };
  const restored = importWorkspace(exportWorkspace({ ...workspace(), pendingOperations: [pending] }));
  const recovered = recoverPendingOperations(restored);
  assert.equal(recovered.pendingOperations.length, 0);
  assert.match(recovered.projects[0].failures[0].error, /no está confirmado/);
  assert.equal(recovered.projects[0].failures[0].source, 'crtsh');
  assert.equal(recoverPendingOperations(recovered).projects[0].failures.length, 1);
});

test('El límite del historial conserva los últimos registros sin modificar evidencias ni ejecuciones', () => {
  let data = workspace();
  for (let i = 0; i <= FAILURE_LIMIT; i++) data = appendFailure(data, 'a', failure({ id: `failure${i}` }));
  assert.equal(data.projects[0].failures.length, FAILURE_LIMIT);
  assert.equal(data.projects[0].failures[0].id, `failure${FAILURE_LIMIT}`);
  assert.equal(data.projects[0].failures.at(-1).id, 'failure1');
  assert.equal(data.projects[0].executions, 0);
});
