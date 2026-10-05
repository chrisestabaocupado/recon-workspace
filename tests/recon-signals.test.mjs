import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { approveScopePlan, newScopePlan } from '../src/lib/scope.ts';
import { buildReconCommand, mergeReconResult, parseDnsResult, reconQueryIssues, validateReconQuery, validateReconData } from '../src/lib/recon.ts';
import { collectReconSignals } from '../src/server/recon-signals.ts';

const now = Date.parse('2026-10-02T12:00:00Z');
const domain = 'scope-lab.net';
const query = { source: 'dns', domain, subdomains: false, timeoutSeconds: 25 };
function plan() {
  return approveScopePlan({ ...newScopePlan(), passiveRecon: true, organization: 'Lab', objective: 'Synthetic', assessor: 'Operator', authorizer: 'Owner', authorizationReference: 'SIMULATED', includes: [domain], excludes: [], windowStart: '2026-10-02T11:00:00Z', windowEnd: '2026-10-02T18:00:00Z', contactName: 'Contact', contactChannel: 'Test', incidentName: 'Contact', incidentChannel: 'Test', sourceDescription: 'Synthetic' }, true, now);
}
const dnsPayload = () => ({ resolvers: ['192.0.2.53'], rows: [
  { type: 'A', values: ['192.0.2.10'] },
  { type: 'AAAA', values: ['2001:db8::10'] },
  { type: 'CNAME', values: ['mail.provider.net'] },
  { type: 'MX', values: [{ priority: 10, exchange: 'mx.provider.net' }] },
  { type: 'NS', values: ['ns.provider.net'] },
  { type: 'TXT', values: [['v=spf1 ', '-all']] },
  { type: 'SOA', values: [{ nsname: 'ns.provider.net', serial: 2026100201 }] },
] });
const cert = { address: '192.0.2.10', subject: domain, issuer: 'Lab CA', san: `DNS:${domain}, DNS:mail.provider.net, DNS:*.${domain}`, validFrom: 'Oct 1 2026', validTo: 'Oct 1 2027', fingerprint: 'AA:BB', protocol: 'TLSv1.3', authorized: false, authorizationError: 'SELF_SIGNED_CERT', hostnameError: '' };

test('DNS conserva registros, candidatos y procedencia sin consultar padres ni candidatos', async () => {
  const calls = [];
  const result = await collectReconSignals(query, plan(), async (payload) => { calls.push(payload); return dnsPayload(); }, () => now);
  assert.deepEqual(calls, [{ operation: 'dns', domain, timeoutMs: 25000 }]);
  assert.equal(result.source, 'dns');
  assert.equal(result.scopeRevision, 1);
  assert.equal(result.sourceUrl, '');
  assert.ok(result.assets.includes('mx.provider.net'));
  assert.ok(result.assets.includes('2001:db8::10'));
  assert.equal(result.facts.find((f) => f.label === 'TXT').value, 'v=spf1 -all');
  const saved = mergeReconResult(undefined, result);
  assert.equal(validateReconData(JSON.parse(JSON.stringify(saved))).evidence[0].source, 'dns');
});

test('DNS diferencia ausencia, fallo parcial y fallo total; rechaza respuesta incompleta o inválida', () => {
  const partial = dnsPayload(); partial.rows[1] = { type: 'AAAA', values: [], error: 'ENODATA' }; partial.rows[3] = { type: 'MX', values: [], error: 'ETIMEOUT' };
  const result = parseDnsResult(partial, domain);
  assert.ok(result.warnings.some((w) => w.includes('MX') && w.includes('ETIMEOUT')));
  assert.ok(!result.warnings.some((w) => w.includes('ENODATA')));
  assert.throws(() => parseDnsResult({ ...partial, rows: partial.rows.slice(1) }, domain), /incompleta/);
  const invalid = dnsPayload(); invalid.rows[0].values = ['192.0.2.0/24'];
  assert.throws(() => parseDnsResult(invalid, domain), /Dirección/);
  const failed = dnsPayload(); failed.rows = failed.rows.map((r) => ({ type: r.type, values: [], error: 'ETIMEOUT' }));
  assert.throws(() => parseDnsResult(failed, domain), /No se pudo consultar DNS/);
  const absent = { ...failed, rows: failed.rows.map((r) => ({ ...r, error: 'ENOTFOUND' })) };
  assert.deepEqual(parseDnsResult(absent, domain).assets, []);
});

test('TLS requiere permisos activos y puerto autorizado; no hereda permiso del reconocimiento pasivo', async () => {
  const tlsQuery = { ...query, source: 'tls', port: 443 };
  assert.ok(reconQueryIssues(tlsQuery, { ...plan(), techniques: { ...plan().techniques, tcp: false } }, now).length);
  assert.ok(reconQueryIssues(tlsQuery, { ...plan(), allowedPorts: '22' }, now).length);
  assert.deepEqual(reconQueryIssues(tlsQuery, { ...plan(), passiveRecon: false }, now), []);
  let calls = 0;
  await assert.rejects(collectReconSignals(tlsQuery, { ...plan(), allowedPorts: '22' }, async () => { calls++; }, () => now));
  assert.equal(calls, 0);
  assert.throws(() => validateReconQuery({ ...tlsQuery, port: 65536 }));
  assert.throws(() => validateReconQuery({ ...query, subdomains: true }));
});

test('TLS fija la IP, guarda el certificado y no sigue los nombres SAN', async () => {
  const calls = [];
  const result = await collectReconSignals({ ...query, source: 'tls', port: 443 }, plan(), async (payload) => {
    calls.push(payload); return payload.operation === 'resolve' ? { [domain]: ['192.0.2.10'] } : cert;
  }, () => now);
  assert.deepEqual(calls.map((c) => c.operation), ['resolve', 'tls']);
  assert.equal(calls[1].address, '192.0.2.10');
  assert.ok(result.assets.includes('mail.provider.net'));
  assert.ok(!result.assets.some((a) => a.startsWith('*.')));
  assert.ok(result.warnings.some((w) => w.includes('SELF_SIGNED_CERT')));
  assert.equal(mergeReconResult(undefined, result).evidence[0].source, 'tls');
});

test('TLS detiene conexiones a exclusiones IP o alias y no consulta después del timeout', async () => {
  const tlsQuery = { ...query, source: 'tls', port: 443 };
  for (const excludes of [['192.0.2.0/24'], ['blocked.provider.net']]) {
    const calls = [];
    await assert.rejects(collectReconSignals(tlsQuery, { ...plan(), excludes }, async (payload) => {
      calls.push(payload); return { [domain]: ['192.0.2.10'], 'blocked.provider.net': ['192.0.2.10'] };
    }, () => now), /exclusión/);
    assert.equal(calls.length, 1);
  }
  let clock = now; let calls = 0;
  await assert.rejects(collectReconSignals(tlsQuery, plan(), async () => { calls++; clock += 26000; return { [domain]: ['192.0.2.10'] }; }, () => clock), /timeout/);
  assert.equal(calls, 1);
});

test('Runner DNS produce las siete respuestas estructuradas con un resolvedor simulado', async () => {
  const source = (await readFile(new URL('../src/server/remote-signals.mjs', import.meta.url), 'utf8')).replace('import { Resolver } from "node:dns/promises";', `const Resolver = class { getServers() { return ['192.0.2.53']; } cancel() {} async resolve(domain, type) { if (type === 'A') return ['192.0.2.10']; const e = new Error(); e.code = 'ENODATA'; throw e; } };`);
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: ['pipe', 'pipe', 'pipe'] });
  let output = ''; let errors = '';
  child.stdout.on('data', (chunk) => { output += chunk; }); child.stderr.on('data', (chunk) => { errors += chunk; });
  child.stdin.end(JSON.stringify({ operation: 'dns', domain, timeoutMs: 1000 }));
  const exit = await new Promise((resolve, reject) => { child.on('close', resolve); child.on('error', reject); });
  assert.equal(exit, 0, errors);
  assert.ok(parseDnsResult(JSON.parse(output), domain).assets.includes('192.0.2.10'));
  assert.ok(buildReconCommand(query).includes('SOA'));
});
