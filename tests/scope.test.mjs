import assert from 'node:assert/strict'
import test from 'node:test'
import { addressRange, approvalIssues, approveScopePlan, newScopePlan, normalizeScopeEntry, pinResolvedScope, reviseScopePlan, scopedCommandIssues, scopeLines, targetDecision, validateScopePlan } from '../src/lib/scope.ts'
import { exportWorkspace, importWorkspace, validateWorkspace } from '../src/lib/storage.ts'
import { saveProjectPlan } from '../src/lib/planning-project.ts'

const now = Date.parse('2026-10-01T12:00:00Z')
function ready() {
  return { ...newScopePlan(), organization: 'Laboratorio', objective: 'Verificar inventario', assessor: 'Operador del laboratorio', authorizer: 'Propietario del laboratorio', authorizationReference: 'LAB-001 (simulado)', includes: ['192.0.2.0/24', 'lab.test'], excludes: ['192.0.2.99'], windowStart: '2026-10-01T11:00:00Z', windowEnd: '2026-10-01T14:00:00Z', contactName: 'Coordinación', contactChannel: 'canal de laboratorio', incidentName: 'Responsable de incidentes', incidentChannel: 'canal de emergencia', sourceDescription: 'VM Kali aislada' }
}
const approved = () => approveScopePlan(ready(), true, now)
const command = (...extra) => ['-sT', '-Pn', '--max-rate', '50', '-p', '22,80', ...extra, '192.0.2.10']

test('Aprobación requiere datos completos y confirmación externa; cambios invalidan su revisión', () => {
  assert.ok(approvalIssues(newScopePlan(), now).length > 0)
  assert.throws(() => approveScopePlan(ready(), false, now), /Confirma/)
  assert.throws(() => approveScopePlan({ ...ready(), authorizationReference: '' }, true, now), /autorización escrita/)
  const plan = approved()
  assert.equal(plan.status, 'approved')
  assert.equal(plan.approvedAt, new Date(now).toISOString())
  const changed = reviseScopePlan(plan)
  assert.equal(changed.revision, 2)
  assert.equal(changed.status, 'draft')
  assert.equal(changed.approvalAttested, false)
  assert.equal(changed.approvedAt, undefined)
})
test('IP/CIDR IPv4 e IPv6 comprueban pertenencia completa y exclusiones prevalentes', () => {
  const plan = { ...ready(), includes: ['192.0.2.0/24', '2001:db8::/64'], excludes: ['192.0.2.99', '2001:db8::ff'] }
  assert.equal(targetDecision('192.0.2.10', plan).allowed, true)
  assert.equal(targetDecision('192.0.3.10', plan).allowed, false)
  assert.equal(targetDecision('192.0.2.0/24', plan).allowed, false)
  assert.equal(targetDecision('192.0.2.128/25', plan).allowed, true)
  assert.equal(targetDecision('2001:db8::1', plan).allowed, true)
  assert.equal(targetDecision('2001:db8::/64', plan).allowed, false)
  assert.equal(addressRange('192.0.2.1/24').count, 256n)
  assert.equal(addressRange('2001:db8::/64').count, 1n << 64n)
})
test('Dominios exactos se normalizan; no heredan subdominios, URLs ni rangos ambiguos', () => {
  assert.deepEqual(scopeLines('LAB.TEST.\nlab.test\n192.0.2.10'), ['lab.test', '192.0.2.10'])
  assert.equal(targetDecision('child.lab.test', ready()).allowed, false)
  for (const invalid of ['*.lab.test', 'http://lab.test/a', '192.0.2.1-20', '127.1', '192.0.002.10', '::ffff:192.0.2.10', 'fe80::1%eth0', '192.0.2.0/33']) assert.throws(() => normalizeScopeEntry(invalid), invalid)
})
test('Importación conserva planes e historial antiguo; rechaza estructuras y aprobaciones incompletas', () => {
  const project = { id: 'lab', name: 'Lab', scope: '192.0.2.0/24', createdAt: new Date(now).toISOString(), targets: [], executions: 0 }
  const original = { projects: [project], selectedProjectId: 'lab' }
  assert.equal(validateWorkspace(original).projects[0].plan, undefined)
  const data = { ...original, projects: [{ ...project, plan: approved() }] }
  assert.equal(importWorkspace(exportWorkspace(data)).projects[0].plan.authorizationReference, data.projects[0].plan.authorizationReference)
  for (const malformed of [{ ...approved(), approvalAttested: false }, { ...approved(), techniques: { tcp: true } }, { ...approved(), maxHosts: -1 }, { ...approved(), windowEnd: 'ayer' }, { ...approved(), includes: ['*'] }]) assert.throws(() => validateScopePlan(malformed))
})
test('Ventana, estado y máximo de duración se verifican antes de iniciar', () => {
  assert.deepEqual(scopedCommandIssues(command(), approved(), 60, now), [])
  assert.ok(scopedCommandIssues(command(), undefined, 60, now).length)
  for (const status of ['draft', 'paused', 'closed']) assert.ok(scopedCommandIssues(command(), { ...approved(), status }, 60, now).some((error) => /aprobado/.test(error)))
  assert.ok(scopedCommandIssues(command(), approved(), 60, Date.parse('2026-10-01T10:00:00Z')).some((error) => /ventana/.test(error)))
  assert.ok(scopedCommandIssues(command(), approved(), 60, Date.parse('2026-10-01T13:59:30Z')).some((error) => /timeout/.test(error)))
  assert.ok(scopedCommandIssues(command(), approved(), 601, now).some((error) => /timeout/.test(error)))
})
test('Límites de objetivos y tasa y destinos indirectos no pueden omitirse', () => {
  const plan = { ...approved(), excludes: [] }
  assert.ok(scopedCommandIssues(['-sT', '--max-rate', '50', '192.0.2.0/24'], plan, 60, now).some((error) => /256 direcciones/.test(error)))
  assert.ok(scopedCommandIssues(['-sT', '192.0.2.10'], plan, 60, now).some((error) => /max-rate/.test(error)))
  assert.ok(scopedCommandIssues(command('--max-rate', '101'), plan, 60, now).some((error) => /max-rate/.test(error)))
  for (const extra of [['-iL', 'targets.txt'], ['-iR', '5'], ['--script', 'safe'], ['-A'], ['--resolve-all'], ['--future', 'option']]) assert.ok(scopedCommandIssues(command(...extra), plan, 60, now).length > 0)
  assert.deepEqual(scopedCommandIssues(['--version'], undefined, 60, now), [])
  assert.ok(scopedCommandIssues(['--version', '192.0.2.10'], undefined, 60, now).length > 0)
})
test('Técnicas y puertos restringidos validan todos los intervalos y combinaciones TCP/UDP', () => {
  const plan = { ...approved(), allowedPorts: '22,80,443' }
  assert.deepEqual(scopedCommandIssues(command(), plan, 60, now), [])
  assert.ok(scopedCommandIssues(['-sT', '-Pn', '-p', '20-80', '--max-rate', '50', '192.0.2.10'], plan, 60, now).some((error) => /puertos.*exceden/.test(error)))
  assert.ok(scopedCommandIssues(['-sT', '-p', '80', '--max-rate', '50', '192.0.2.10'], plan, 60, now).some((error) => /sondas/.test(error)))
  assert.ok(scopedCommandIssues(command('-sU'), plan, 60, now).some((error) => /UDP/.test(error)))
  assert.ok(scopedCommandIssues(command('-sV'), { ...plan, techniques: { ...plan.techniques, services: false } }, 60, now).some((error) => /versiones/.test(error)))
  assert.ok(scopedCommandIssues(command('-sU'), { ...plan, techniques: { ...plan.techniques, tcp: false, udp: true } }, 60, now).some((error) => /TCP/.test(error)))
  assert.ok(scopedCommandIssues(['-6', '-Pn', '--max-rate', '50', '192.0.2.10'], approved(), 60, now).some((error) => /familia/.test(error)))
})
test('DNS se fija a una IP y respeta exclusiones IP y alias DNS con datos sintéticos', () => {
  const args = ['-sT', '-Pn', '--max-rate', '50', '-oX', '-', '--', 'lab.test']
  assert.deepEqual(pinResolvedScope(args, approved(), { 'lab.test': ['192.0.2.10', '192.0.2.11'] }, 60, now), ['-sT', '-Pn', '--max-rate', '50', '-oX', '-', '--', '192.0.2.10'])
  assert.throws(() => pinResolvedScope(args, approved(), { 'lab.test': ['192.0.2.10', '192.0.2.99'] }, 60, now), /exclusión/)
  const alias = { ...approved(), excludes: ['protected.test'] }
  assert.throws(() => pinResolvedScope(args, alias, { 'lab.test': ['192.0.2.10'], 'protected.test': ['192.0.2.10'] }, 60, now), /exclusión/)
  assert.throws(() => pinResolvedScope(command(), alias, { 'protected.test': ['192.0.2.10'] }, 60, now), /exclusión/)
  assert.throws(() => pinResolvedScope(args, approved(), { 'lab.test': ['2001:db8::1'] }, 60, now), /otra familia/)
  assert.throws(() => pinResolvedScope(args, approved(), {}, 60, now), /resolver/)
})

test('Guardar una nueva revisión conserva las reglas anteriores y sus referencias al exportar', () => {
  const current = approved()
  const workspace = { projects: [{ id: 'lab', name: 'Lab', scope: current.includes.join(', '), createdAt: new Date(now).toISOString(), targets: [], executions: 1, plan: current, lastRuns: [{ id: 'run', scopeRevision: 1, command: 'nmap -sT 192.0.2.10', state: 'completed', date: new Date(now).toISOString(), excerpt: '' }] }], selectedProjectId: 'lab' }
  const changed = { ...reviseScopePlan(current), includes: ['192.0.2.20'] }
  const saved = saveProjectPlan(workspace, 'lab', 'Lab actualizado', changed)
  assert.equal(saved.projects[0].plan.status, 'draft')
  assert.deepEqual(saved.projects[0].planHistory[0].includes, current.includes)
  assert.equal(saved.projects[0].lastRuns[0].scopeRevision, 1)
  const exported = importWorkspace(exportWorkspace(saved))
  assert.equal(exported.projects[0].planHistory[0].authorizationReference, current.authorizationReference)
  changed.includes.push('192.0.2.30')
  assert.deepEqual(saved.projects[0].plan.includes, ['192.0.2.20'])
  assert.throws(() => saveProjectPlan(workspace, 'missing', 'Lab', current), /ya no existe/)
})
