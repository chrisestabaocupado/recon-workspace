import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { approveScopePlan, newScopePlan } from '../src/lib/scope.ts';
import { buildReconCommand, mergeReconResult, parseDnsResult, parsePtrResult, reconQueryIssues, reconQueryUrl, validateReconQuery, validateReconData } from '../src/lib/recon.ts';
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

const ipPlan = (address = '172.16.10.24') => ({ ...plan(), includes: [address] });
const ptrPayload = (address = '172.16.10.24') => ({ address, names: ['GLPI.INTERNAL.', 'glpi.internal'], resolvers: ['172.16.10.1'] });

test('Consultas DNS/TLS admiten IP individuales; fuentes públicas y CIDR siguen restringidos', () => {
  for (const address of ['172.16.10.24', '2001:db8::24']) {
    for (const source of ['dns', 'tls']) {
      assert.equal(validateReconQuery({ ...query, source, domain: address }).domain, address);
      assert.deepEqual(reconQueryIssues({ ...query, source, domain: address }, ipPlan(address), now), []);
      for (const domain of ['172.16.10.0/24', '172.16.10.24/32', '2001:db8::/64', '2001:db8::24/128'])
        assert.throws(() => validateReconQuery({ ...query, source, domain }), /IP individual/);
    }
    for (const source of ['crtsh', 'rdap']) assert.throws(() => validateReconQuery({ ...query, source, domain: address }), /dominio público/);
  }
  for (const domain of ['172.16.010.24', 'https://172.16.10.24', '2001:db8::zz', '::ffff:172.16.10.24'])
    assert.throws(() => validateReconQuery({ ...query, domain }));
  assert.match(buildReconCommand({ ...query, domain: '172.16.10.24' }), /-x 172\.16\.10\.24/);
  const tlsQuery = { ...query, source: 'tls', domain: '2001:db8::24', port: 8443 };
  assert.equal(reconQueryUrl(tlsQuery), 'https://[2001:db8::24]:8443/');
  assert.match(buildReconCommand(tlsQuery), /\[2001:db8::24\]:8443.*-noservername/);
});

test('DNS inverso conserva PTR internos y trazabilidad sin resolver ni contactar candidatos', async () => {
  for (const address of ['172.16.10.24', '2001:db8::24']) {
    const calls = [];
    const result = await collectReconSignals({ ...query, domain: address }, ipPlan(address), async (payload) => {
      calls.push(payload); return ptrPayload(address);
    }, () => now);
    assert.deepEqual(calls, [{ operation: 'reverse', address, timeoutMs: 25000 }]);
    assert.deepEqual(result.assets, [address, 'glpi.internal']);
    assert.equal(result.query, address);
    assert.equal(result.facts.find((f) => f.label === 'PTR').value, 'glpi.internal');
    assert.equal(result.scopeRevision, 1);
    assert.equal(validateReconData(JSON.parse(JSON.stringify(mergeReconResult(undefined, result)))).evidence[0].query, address);
  }
});

test('PTR diferencia ausencia y fallos, rechaza respuestas contradictorias y de otro destino', () => {
  const address = '172.16.10.24';
  for (const error of ['ENOTFOUND', 'ENODATA', undefined]) {
    const result = parsePtrResult({ ...ptrPayload(), names: [], error }, address);
    assert.deepEqual(result.assets, []);
    assert.match(result.facts.find((f) => f.label === 'PTR').value, /Sin registros PTR/);
  }
  assert.throws(() => parsePtrResult({ ...ptrPayload(), names: [], error: 'ETIMEOUT' }, address), /ETIMEOUT/);
  assert.throws(() => parsePtrResult({ ...ptrPayload(), error: 'ENOTFOUND' }, address), /contradictoria/);
  assert.throws(() => parsePtrResult(ptrPayload('172.16.10.25'), address), /IP distinta/);
  for (const names of [['172.16.10.1'], ['*.internal'], ['https://glpi.internal'], Array(101).fill('glpi.internal')])
    assert.throws(() => parsePtrResult({ ...ptrPayload(), names }, address));
  const names = Array.from({ length: 100 }, (_, index) => `${'a'.repeat(60)}.${'b'.repeat(60)}.${index}.internal`);
  const parsed = parsePtrResult({ ...ptrPayload(), names }, address);
  const saved = mergeReconResult(undefined, { ...parsed, source: 'dns', query: address, sourceUrl: '', retrievedAt: new Date(now).toISOString() });
  assert.equal(validateReconData(JSON.parse(JSON.stringify(saved))).assets.length, 101);
});

test('TLS por IP no resuelve el objetivo y conserva evidencia, puerto y advertencia sin SNI', async () => {
  for (const address of ['172.16.10.24', '2001:db8::24']) {
    const calls = [];
    const result = await collectReconSignals({ ...query, source: 'tls', domain: address, port: 8443 }, ipPlan(address), async (payload) => {
      calls.push(payload); return { ...cert, address };
    }, () => now);
    assert.deepEqual(calls, [{ operation: 'tls', domain: address, address, port: 8443, timeoutMs: 25000 }]);
    assert.ok(result.warnings.some((w) => w.includes('sin SNI')));
    assert.ok(result.assets.includes(address));
    assert.equal(validateReconData(JSON.parse(JSON.stringify(mergeReconResult(undefined, result)))).evidence[0].query, address);
  }
});

test('IP respeta alcance, permisos, puertos y ventana antes de invocar Kali', async () => {
  const address = '172.16.10.24';
  for (const source of ['dns', 'tls']) {
    const input = { ...query, source, domain: address, port: 443 };
    const base = ipPlan();
    const denied = [
      { ...base, includes: ['172.16.11.0/24'] },
      { ...base, excludes: [address] },
      { ...base, excludes: ['172.16.10.0/24'] },
      { ...base, status: 'paused' },
      { ...base, windowEnd: new Date(now + 10000).toISOString() },
      ...(source === 'dns' ? [{ ...base, passiveRecon: false }] : [
        { ...base, techniques: { ...base.techniques, tcp: false } },
        { ...base, techniques: { ...base.techniques, services: false } },
        { ...base, allowedPorts: '80' },
      ]),
    ];
    for (const scope of denied) {
      let calls = 0;
      await assert.rejects(collectReconSignals(input, scope, async () => { calls++; }, () => now));
      assert.equal(calls, 0);
    }
  }
});

test('TLS por IP comprueba alias excluidos, también en IPv6, y falla de forma cerrada', async () => {
  for (const address of ['172.16.10.24', '2001:db8::24']) {
    const calls = [];
    await assert.rejects(collectReconSignals({ ...query, source: 'tls', domain: address }, { ...ipPlan(address), excludes: ['blocked.internal'] }, async (payload) => {
      calls.push(payload); return { 'blocked.internal': [address] };
    }, () => now), /exclusión/);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].names, ['blocked.internal']);
    assert.equal(calls[0].family, address.includes(':') ? 6 : undefined);
    await assert.rejects(collectReconSignals({ ...query, source: 'tls', domain: address }, { ...ipPlan(address), excludes: ['blocked.internal'] }, async () => ({}), () => now), /resolver/);
  }
});

test('Reconocimiento por IP rechaza resultados que llegan después del timeout', async () => {
  for (const source of ['dns', 'tls']) {
    let clock = now;
    await assert.rejects(collectReconSignals({ ...query, source, domain: '172.16.10.24' }, ipPlan(), async () => {
      clock += 26000; return source === 'dns' ? ptrPayload() : { ...cert, address: '172.16.10.24' };
    }, () => clock), /timeout/);
  }
});

async function runSignalRunner(source, payload) {
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: ['pipe', 'pipe', 'pipe'] });
  let output = ''; let errors = '';
  child.stdout.on('data', (chunk) => { output += chunk; }); child.stderr.on('data', (chunk) => { errors += chunk; });
  child.stdin.end(JSON.stringify({ timeoutMs: 1000, ...payload }));
  const exit = await new Promise((resolve, reject) => { child.on('close', resolve); child.on('error', reject); });
  return { exit, output, errors };
}

test('Runner PTR usa reverse para IPv4/IPv6 y conserva errores del resolvedor', async () => {
  const source = (await readFile(new URL('../src/server/remote-signals.mjs', import.meta.url), 'utf8')).replace('import { Resolver } from "node:dns/promises";', `const Resolver = class { getServers() { return ['192.0.2.53']; } cancel() {} async reverse(address) { if (address === '172.16.10.24') return ['glpi.internal']; const e = new Error(); e.code = 'ENOTFOUND'; throw e; } };`);
  for (const address of ['172.16.10.24', '2001:db8::24']) {
    const result = await runSignalRunner(source, { operation: 'reverse', address });
    assert.equal(result.exit, 0, result.errors);
    assert.equal(parsePtrResult(JSON.parse(result.output), address).assets.length, address.includes(':') ? 0 : 2);
  }
  assert.equal((await runSignalRunner(source, { operation: 'reverse', address: '172.16.10.0/24' })).exit, 1);
});

test('Runner resuelve exclusiones DNS en la familia del destino TLS', async () => {
  const source = (await readFile(new URL('../src/server/remote-signals.mjs', import.meta.url), 'utf8')).replace('import { Resolver } from "node:dns/promises";', `const Resolver = class { cancel() {} async resolve4() { return ['192.0.2.10']; } async resolve6() { return ['2001:db8::10']; } };`);
  for (const family of [undefined, 6]) {
    const result = await runSignalRunner(source, { operation: 'resolve', names: ['blocked.internal'], family });
    assert.equal(result.exit, 0, result.errors);
    assert.deepEqual(JSON.parse(result.output), { 'blocked.internal': [family === 6 ? '2001:db8::10' : '192.0.2.10'] });
  }
});

test('Runner TLS omite SNI para IP, mantiene SNI para dominios y verifica identidad contra el objetivo', async () => {
  const source = (await readFile(new URL('../src/server/remote-signals.mjs', import.meta.url), 'utf8')).replace('import tls from "node:tls";', `
    import { EventEmitter } from 'node:events';
    const tls = {
      connect(options) {
        const socket = new EventEmitter(); socket.authorized = false; socket.authorizationError = 'SELF_SIGNED_CERT';
        socket.getPeerCertificate = () => ({ fingerprint256: 'AA:BB', subject: { CN: options.servername ?? 'sin SNI' } });
        socket.getProtocol = () => 'TLSv1.3'; socket.destroy = () => socket.emit('close');
        queueMicrotask(() => socket.emit('secureConnect')); return socket;
      },
      checkServerIdentity(name) { return new Error('identity:' + name); }
    };
  `);
  for (const target of ['172.16.10.24', '2001:db8::24', domain]) {
    const address = target === domain ? '192.0.2.10' : target;
    const result = await runSignalRunner(source, { operation: 'tls', domain: target, address, port: 443 });
    assert.equal(result.exit, 0, result.errors);
    const payload = JSON.parse(result.output);
    assert.equal(payload.subject, target === domain ? domain : 'sin SNI');
    assert.equal(payload.hostnameError, 'identity:' + target);
  }
  assert.equal((await runSignalRunner(source, { operation: 'tls', domain: '172.16.10.24', address: '172.16.10.25', port: 443 })).exit, 1);
});
