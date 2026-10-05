import assert from 'node:assert/strict'
import test from 'node:test'
import { buildReconCommand, emptyRecon, mergeReconResult, parseCrtResult, parseRdapResult, parseReconCommand, publicDomain, reconQueryIssues, removeReconEvidence, scopeManualResult, validateReconData } from '../src/lib/recon.ts'
import { deleteReconEvidence, editReconAsset, promoteReconAsset, saveReconResult } from '../src/lib/recon-project.ts'
import { approveScopePlan, newScopePlan, validateScopePlan } from '../src/lib/scope.ts'
import { exportWorkspace, importWorkspace, validateWorkspace } from '../src/lib/storage.ts'
import { collectRecon, RDAP_BOOTSTRAP_URL, rdapDomainUrl, readReconJson } from '../src/server/recon-service.ts'

const now = Date.parse('2026-10-01T12:00:00Z')
const seed = 'scope-lab.net'
const query = { source: 'crtsh', domain: seed, subdomains: true, timeoutSeconds: 25 }
function plan() {
  return approveScopePlan({ ...newScopePlan(), passiveRecon: true, organization: 'Laboratorio simulado', objective: 'Inventario sintético', assessor: 'Operador', authorizer: 'Responsable ficticio', authorizationReference: 'SIMULADO', includes: [seed, 'app.scope-lab.net', '192.0.2.0/24'], excludes: ['blocked.scope-lab.net', '192.0.2.99'], windowStart: '2026-10-01T11:00:00Z', windowEnd: '2026-10-01T18:00:00Z', contactName: 'Coordinación', contactChannel: 'canal simulado', incidentName: 'Incidentes', incidentChannel: 'canal simulado', sourceDescription: 'Entorno simulado' }, true, now)
}
const ids = () => { let id = 0; return () => `recon-${++id}` }
const manual = (values = 'app.scope-lab.net\nblocked.scope-lab.net\nnew.scope-lab.net') => scopeManualResult(values, 'Inventario sintético', '', new Date(now).toISOString(), 1)
const workspace = () => ({ selectedProjectId: 'p1', projects: [{ id: 'p1', name: 'Laboratorio', createdAt: new Date(now).toISOString(), scope: seed, targets: [], executions: 0, plan: plan() }, { id: 'p2', name: 'Otro proyecto', createdAt: new Date(now).toISOString(), scope: '', targets: [], executions: 0 }] })
const json = (value) => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } })

test('Consulta de fuentes exige dominio público exacto, aprobación, permiso pasivo y ventana', () => {
  for (const domain of ['192.0.2.10', '192.0.2.0/24', 'localhost', 'lab.test', 'intranet.local', '*.scope-lab.net', 'https://scope-lab.net/', 'example.com']) assert.throws(() => publicDomain(domain))
  assert.equal(publicDomain('APP.SCOPE-LAB.NET.'), 'app.scope-lab.net')
  assert.deepEqual(reconQueryIssues(query, plan(), now), [])
  assert.ok(reconQueryIssues(query, newScopePlan(), now).length)
  assert.ok(reconQueryIssues(query, { ...plan(), passiveRecon: false }, now).some((e) => /pasivo/.test(e)))
  assert.ok(reconQueryIssues(query, { ...plan(), status: 'paused' }, now).length)
  assert.ok(reconQueryIssues({ ...query, domain: 'blocked.scope-lab.net' }, plan(), now).length)
  assert.ok(reconQueryIssues({ ...query, domain: 'new.scope-lab.net' }, plan(), now).length)
  assert.ok(reconQueryIssues(query, plan(), now - 7200000).some((e) => /comenzado/.test(e)))
  assert.ok(reconQueryIssues(query, plan(), Date.parse(plan().windowEnd) - 1000).length)
  assert.ok(reconQueryIssues(query, { ...plan(), maxDurationSeconds: 10 }, now).length)
})

test('Planes anteriores conservan su aprobación y no adquieren permiso pasivo automáticamente', () => {
  const legacy = plan(); delete legacy.passiveRecon
  const loaded = validateScopePlan(legacy)
  assert.equal(loaded.passiveRecon, false)
  assert.equal(loaded.status, 'approved')
  assert.throws(() => validateScopePlan({ ...plan(), passiveRecon: 'true' }))
})

test('Campos y CLI curl hacen roundtrip con ambas fuentes, filtros y timeout', () => {
  for (const source of ['crtsh', 'rdap']) for (const timeoutSeconds of [5, 25, 60]) {
    const input = { ...query, source, timeoutSeconds, subdomains: source === 'crtsh' }
    assert.deepEqual(parseReconCommand(buildReconCommand(input)), input)
  }
  const exact = { ...query, subdomains: false }
  assert.deepEqual(parseReconCommand(buildReconCommand(exact)), exact)
  assert.deepEqual(parseReconCommand(`curl.exe -fsSL -m 15 'https://rdap.org/domain/${seed}'`), { source: 'rdap', domain: seed, subdomains: false, timeoutSeconds: 15 })
})

test('CLI rechaza shell, URLs ajenas, credenciales, duplicados y opciones que no cubre el adaptador', () => {
  for (const command of [
    `curl https://127.0.0.1/`,
    `curl 'https://user:pass@crt.sh/?q=${seed}&output=json'`,
    `curl --header 'Authorization: secret' 'https://crt.sh/?q=${seed}&output=json'`,
    `curl --location 'https://crt.sh/?q=${seed}&output=json'`,
    `curl 'https://rdap.org/domain/${seed}'`,
    `curl 'https://crt.sh/?q=${seed}&q=other.net&output=json'`,
    `curl --max-time 5 --max-time 20 'https://crt.sh/?q=${seed}&output=json'`,
    `curl --max-time 61 'https://crt.sh/?q=${seed}&output=json'`,
    `${buildReconCommand(query)}; nmap 192.0.2.1`,
  ]) assert.throws(() => parseReconCommand(command))
})

test('Certificados deduplican SAN, ignoran comodines y dominios ajenos, y no inventan hosts', () => {
  const data = [{ name_value: `APP.${seed}\n*.${seed}\n${seed}\nevil-scope-lab.net\n${seed}.evil.net` }, { name_value: `app.${seed}.\nnew.${seed}` }]
  const result = parseCrtResult(data, query)
  assert.deepEqual(result.assets, [`app.${seed}`, `new.${seed}`, seed].sort())
  assert.ok(result.warnings.some((w) => /comodín/.test(w)))
  assert.deepEqual(parseCrtResult(data, { ...query, subdomains: false }).assets, [seed])
  assert.deepEqual(parseCrtResult([], query).assets, [])
  assert.throws(() => parseCrtResult([{ wrong: 'names' }], query))
  const large = parseCrtResult(Array.from({ length: 520 }, (_, i) => ({ name_value: `host${i}.${seed}` })), query)
  assert.equal(large.assets.length, 500)
  assert.ok(large.warnings.some((w) => /parcial/.test(w)))
})

test('RDAP conserva registro, fechas y DNS, excluye contactos y verifica el dominio devuelto', () => {
  const result = parseRdapResult({ ldhName: seed.toUpperCase(), status: ['active'], events: [{ eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' }], nameservers: [{ ldhName: 'ns.provider.net' }, { ldhName: 'ns.provider.net' }], entities: [{ handle: 'R123', roles: ['registrar'], vcardArray: ['vcard', [['email', {}, 'text', 'private@person.net']]] }, { handle: 'PERSON', roles: ['registrant'] }] }, seed)
  assert.deepEqual(result.assets, [seed, 'ns.provider.net'])
  assert.ok(!JSON.stringify(result).includes('private@person.net'))
  assert.ok(!JSON.stringify(result).includes('PERSON'))
  assert.throws(() => parseRdapResult({ ldhName: 'other.net' }, seed), /distinto/)
})

test('Evidencia manual normaliza activos y exige fechas, fuentes seguras y tamaño acotado', () => {
  assert.deepEqual(manual(' APP.SCOPE-LAB.NET.\napp.scope-lab.net\n192.0.2.10 ').assets, ['app.scope-lab.net', '192.0.2.10'])
  assert.throws(() => scopeManualResult('', 'Notas', 'javascript:alert(1)', new Date(now).toISOString()))
  assert.throws(() => scopeManualResult('', 'Notas', '', 'no-date'))
  assert.throws(() => manual('https://scope-lab.net/'))
  assert.throws(() => manual(Array.from({ length: 501 }, (_, i) => `host${i}.lab.test`).join('\n')))
})

test('Guardar hallazgos mantiene candidatos separados, fuentes múltiples y revisiones del operador', () => {
  const newId = ids()
  let data = mergeReconResult(undefined, manual(), 'token=secret evidencia', newId)
  assert.equal(data.assets.length, 3)
  assert.equal(data.assets[0].status, 'candidate')
  assert.ok(!data.evidence[0].notes.includes('secret'))
  data.assets[0].status = 'discarded'; data.assets[0].note = 'Proveedor fuera del acuerdo'
  const updated = mergeReconResult(data, manual(), '', newId)
  assert.equal(updated.assets.length, 3)
  assert.equal(updated.assets[0].status, 'discarded')
  assert.equal(updated.assets[0].evidenceIds.length, 2)
  assert.equal(data.assets[0].evidenceIds.length, 1)
  const removed = removeReconEvidence(updated, updated.evidence[0].id)
  assert.equal(removed.assets.length, 3)
  assert.equal(removed.assets[0].evidenceIds.length, 1)
  assert.equal(removeReconEvidence(removed, removed.evidence[0].id).assets.length, 0)
})

test('Importar/exportar conserva reconocimiento y compatibilidad, rechaza duplicados y referencias rotas', () => {
  let data = saveReconResult(workspace(), 'p1', manual(), '', ids())
  data = { ...data, selectedProjectId: 'p2' }
  const imported = importWorkspace(exportWorkspace(data))
  assert.equal(imported.projects[0].recon.assets.length, 3)
  assert.equal(imported.selectedProjectId, 'p2')
  assert.equal(validateWorkspace(workspace()).projects[0].recon, undefined)
  const recon = imported.projects[0].recon
  assert.throws(() => validateReconData({ ...recon, assets: [...recon.assets, recon.assets[0]] }))
  assert.throws(() => validateReconData({ ...recon, assets: [{ ...recon.assets[0], evidenceIds: ['missing'] }] }))
  assert.throws(() => validateReconData({ ...recon, evidence: [{ ...recon.evidence[0], sourceUrl: 'data:text/html,unsafe' }] }))
  assert.deepEqual(validateReconData(emptyRecon()), emptyRecon())
})

test('Promoción requiere revisión y plan vigente; respeta exclusiones sin ampliar alcance y no duplica', () => {
  let data = saveReconResult(workspace(), 'p1', manual(), '', ids())
  const [allowed, blocked, outside] = data.projects[0].recon.assets
  assert.throws(() => promoteReconAsset(data, 'p1', allowed.id, now))
  for (const asset of [allowed, blocked, outside]) data = editReconAsset(data, 'p1', asset.id, 'reviewed', 'Revisado', now)
  assert.throws(() => promoteReconAsset(data, 'p1', blocked.id, now), /exclu/)
  assert.throws(() => promoteReconAsset(data, 'p1', outside.id, now), /alcance/)
  const originalPlan = structuredClone(data.projects[0].plan)
  const promoted = promoteReconAsset({ ...data, selectedProjectId: 'p2' }, 'p1', allowed.id, now, () => 'target-1')
  assert.equal(promoted.projects[0].targets[0].value, allowed.value)
  assert.equal(promoted.projects[1].targets.length, 0)
  assert.deepEqual(promoted.projects[0].plan, originalPlan)
  assert.throws(() => promoteReconAsset(promoted, 'p1', allowed.id, now), /ya está/)
  assert.throws(() => promoteReconAsset(data, 'p1', allowed.id, now + 86400000))
  const removed = deleteReconEvidence(promoted, 'p1', promoted.projects[0].recon.evidence[0].id)
  assert.equal(removed.projects[0].targets.length, 1)
  assert.equal(removed.projects[0].recon.assets.length, 0)
})

test('Servicio valida antes de cualquier petición y conserva fuente, fecha y revisión con respuestas simuladas', async () => {
  const calls = []
  const fetcher = async (url, options) => { calls.push([url, options.redirect]); return json([{ name_value: `app.${seed}` }]) }
  await assert.rejects(collectRecon(query, { ...plan(), passiveRecon: false }, fetcher, () => now))
  assert.equal(calls.length, 0)
  const result = await collectRecon(query, plan(), fetcher, () => now)
  assert.equal(calls.length, 1)
  assert.equal(calls[0][1], 'error')
  assert.ok(calls[0][0].startsWith('https://crt.sh/'))
  assert.equal(result.scopeRevision, 1)
  assert.equal(result.retrievedAt, new Date(now).toISOString())
  assert.deepEqual(result.assets, [`app.${seed}`])
})

test('RDAP usa solo endpoint HTTPS publicado por IANA, sin seguir enlaces ni redirecciones del registro', async () => {
  const directory = { services: [[['net'], ['http://insecure.net/', 'https://registry.provider.net/rdap/']]] }
  assert.equal(rdapDomainUrl(directory, seed), `https://registry.provider.net/rdap/domain/${seed}`)
  for (const endpoint of ['http://registry.net/', 'https://127.0.0.1/', 'https://[::1]/', 'https://user:pass@registry.net/', 'https://internal.local/', 'https://registry.net:8443/']) assert.throws(() => rdapDomainUrl({ services: [[['net'], [endpoint]]] }, seed))
  const calls = []
  const result = await collectRecon({ ...query, source: 'rdap', subdomains: false }, plan(), async (url, options) => {
    calls.push(url); assert.equal(options.redirect, 'error')
    return url === RDAP_BOOTSTRAP_URL ? json(directory) : json({ ldhName: seed, links: [{ href: 'http://127.0.0.1/private' }] })
  }, () => now)
  assert.deepEqual(calls, [RDAP_BOOTSTRAP_URL, `https://registry.provider.net/rdap/domain/${seed}`])
  assert.equal(result.sourceUrl, calls[1])
})

test('Respuestas inválidas, parciales, limitadas o demasiado grandes fallan sin guardar hallazgos ficticios', async () => {
  await assert.rejects(readReconJson(new Response('<html>error</html>')), /JSON/)
  await assert.rejects(readReconJson(new Response('{}', { status: 429 })), /429/)
  await assert.rejects(readReconJson(new Response('{}', { status: 404 })), /404/)
  await assert.rejects(readReconJson(new Response('12345678'), 4), /supera/)
  await assert.rejects(readReconJson(new Response('{}', { headers: { 'content-length': '99999999' } })), /supera/)
  await assert.rejects(collectRecon(query, plan(), async () => { throw new TypeError('network failure') }, () => now), /TLS/)
})

test('Los errores 404 corresponden a la fuente consultada y no afirman ausencia de certificados', async () => {
  await assert.rejects(collectRecon(query, plan(), async () => new Response('{}', { status: 404 }), () => now), (error) => {
    assert.match(error.message, /crt\.sh.*404/);
    assert.match(error.message, /no confirma/);
    assert.doesNotMatch(error.message, /RDAP/);
    return true;
  });
  const directory = { services: [[['net'], ['https://registry.provider.net/rdap/']]] };
  await assert.rejects(collectRecon({ ...query, source: 'rdap', subdomains: false }, plan(), async (url) => url === RDAP_BOOTSTRAP_URL ? json(directory) : new Response('{}', { status: 404 }), () => now), /RDAP.*404.*registrable/);
  await assert.rejects(collectRecon({ ...query, source: 'rdap', subdomains: false }, plan(), async () => new Response('{}', { status: 404 }), () => now), (error) => {
    assert.match(error.message, /404/);
    assert.doesNotMatch(error.message, /registrable/);
    return true;
  });
});

test('Servicio no lanza el siguiente paso si se agotó el tiempo durante bootstrap y no acepta respuesta tardía', async () => {
  let clock = now; let calls = 0
  await assert.rejects(collectRecon({ ...query, source: 'rdap', subdomains: false }, plan(), async () => { calls++; clock += 30000; return json({ services: [[['net'], ['https://registry.provider.net/']]] }) }, () => clock), /timeout/)
  assert.equal(calls, 1)
  clock = now
  await assert.rejects(collectRecon(query, plan(), async () => { clock += 30000; return json([]) }, () => clock), /timeout/)
})
