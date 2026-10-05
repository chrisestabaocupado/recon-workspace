import assert from 'node:assert/strict'
import test from 'node:test'
import { buildNmapArgs, buildNmapCommand, parseNmapCommand, tokenizeCommand, validateNmapArgs } from '../src/lib/nmap-command.ts'
import { ACTIVE_JOB_KEY, exportWorkspace, importWorkspace, readActiveExecution, readWorkspaceResult, STORAGE_KEY, writeActiveExecution, writeSshSettings, writeWorkspace } from '../src/lib/storage.ts'
import { redactArgs, redactText, secretValues, StreamRedactor } from '../src/lib/redaction.ts'
import { readNmapReport } from '../src/lib/results.ts'
import { saveExecutionResult } from '../src/lib/execution-history.ts'

const normal = 'Nmap scan report for lab.test (192.0.2.10)\nHost is up.\n80/tcp open http nginx 1.24.0\n443/tcp closed https\nNmap done: 1 IP address (1 host up) scanned\n'
const xml = '<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="lab.test"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0"/></port></ports></host></nmaprun>'
const project = (id = 'a') => ({ id, name: `Proyecto ${id}`, scope: '192.0.2.10', createdAt: '2026-10-01T00:00:00Z', targets: [], executions: 0, lastRuns: [] })
const workspace = () => ({ projects: [project('a'), project('b')], selectedProjectId: 'b' })
const memory = new Map()
globalThis.window = { localStorage: { getItem: (key) => memory.get(key) ?? null, setItem: (key, value) => memory.set(key, value), removeItem: (key) => memory.delete(key) } }

test('CLI conserva argv, separadores, repeticiones, comillas y niveles numéricos', () => {
  for (const command of [
    'nmap -sT -sV -p 22,80,443 -T3 192.0.2.10',
    'nmap -v0 -d9 192.0.2.10',
    'nmap -v2 -v --script-args "http.useragent=dos palabras" 192.0.2.10',
    'nmap -- -example',
    "nmap -oX - --script-args 'name=a\"b' 192.0.2.10",
    'nmap --future-option valor -- 192.0.2.10',
    'nmap -PO -p- 192.0.2.10',
  ]) assert.deepEqual(buildNmapArgs(parseNmapCommand(command)), tokenizeCommand(command).slice(1))
})
test('Editar un campo conserva las demás opciones y su ubicación', () => {
  const config = parseNmapCommand('nmap -sV --script-args "http.useragent=dos palabras" -p80 -- 192.0.2.10')
  config.values.ports = '80,443'
  config.values.verbose = '0'
  assert.deepEqual(buildNmapArgs(config), ['-sV', '--script-args', 'http.useragent=dos palabras', '-p', '80,443', '-v0', '--', '192.0.2.10'])
  assert.equal(parseNmapCommand(buildNmapCommand(config)).values.verbose, '0')
})
test('Rechaza prefijos, shell, valores faltantes, números fuera de rango y comandos incompletos', () => {
  for (const command of ['sudo nmap -p80 192.0.2.10', 'curl 192.0.2.10', 'nmap -p -sV 192.0.2.10', 'nmap -T9 192.0.2.10', 'nmap -p "80', 'nmap 192.0.2.10; echo fallo', 'nmap $(echo target)', 'nmap -e abc\\', 'nmap --resume report.nmap -sV']) assert.throws(() => parseNmapCommand(command), command)
  assert.throws(() => validateNmapArgs(['-p', '-sV', '192.0.2.10']))
  assert.doesNotThrow(() => parseNmapCommand("nmap --data-string 'dato;literal' 192.0.2.10"))
})
test('Importación valida estructura, fechas, contadores, duplicados y tamaño', () => {
  const valid = JSON.parse(exportWorkspace(workspace()))
  assert.equal(importWorkspace(JSON.stringify(valid)).projects.length, 2)
  for (const projects of [[{}], [{ ...project(), targets: [{}] }], [{ ...project(), createdAt: 'ayer' }], [{ ...project(), executions: -1 }], [project(), project()]]) assert.throws(() => importWorkspace(JSON.stringify({ ...valid, projects })))
  assert.throws(() => importWorkspace('x'.repeat(5 * 1024 * 1024 + 1)))
})
test('Lectura de datos corruptos no modifica la copia existente; cuota produce error visible', () => {
  memory.set(STORAGE_KEY, '{corrupto')
  assert.ok(readWorkspaceResult().error)
  assert.equal(memory.get(STORAGE_KEY), '{corrupto')
  const original = window.localStorage.setItem
  window.localStorage.setItem = () => { throw new DOMException('lleno', 'QuotaExceededError') }
  assert.equal(writeWorkspace(workspace()).ok, false)
  window.localStorage.setItem = original
})
test('Se depuran credenciales de historial, exportación y referencias persistidas', () => {
  const data = workspace()
  data.projects[0].lastRuns = [{ id: 'run', command: 'nmap --script-args "smbpassword=DEMO_SECRET,http.useragent=normal" 192.0.2.10', state: 'completed', date: '2026-10-01T00:00:00Z', excerpt: 'password=DEMO_SECRET' }]
  assert.ok(!exportWorkspace(data).includes('DEMO_SECRET'))
  writeActiveExecution({ id: 'id', projectId: 'a', command: data.projects[0].lastRuns[0].command, targets: ['http://user:DEMO_SECRET@lab.test'], mode: 'ssh', startedAt: '2026-10-01T00:00:00Z', passphrase: 'DEMO_SECRET' })
  assert.ok(!memory.get(ACTIVE_JOB_KEY).includes('DEMO_SECRET'))
  assert.equal(readActiveExecution().projectId, 'a')
  writeSshSettings({ host: 'lab', port: 22, username: 'kali', privateKeyPath: 'key', fingerprint: 'SHA256:demo', passphrase: 'DEMO_SECRET' })
  assert.ok(![...memory.values()].some((value) => value.includes('DEMO_SECRET')))
})
test('Redacción funciona entre chunks y conserva XML válido', () => {
  const args = ['--script-args', 'smbpassword=DEMO_SECRET']
  const redactor = new StreamRedactor(secretValues(args))
  const output = redactor.push('password=DEMO_') + redactor.push('SECRET\n') + redactor.flush()
  assert.ok(!output.includes('DEMO_SECRET'))
  const multi = new StreamRedactor(['uno\ndos'])
  assert.ok(!(multi.push('valor=uno\n') + multi.push('dos\n') + multi.flush()).includes('uno\ndos'))
  assert.equal(redactArgs(args)[1], '[REDACTADO]')
  const giantLine = new StreamRedactor(['DEMO_SECRET'])
  const longText = 'x'.repeat(100005 - 1024 - 3) + 'DEMO_SECRET' + 'z'.repeat(1024 - 8)
  const filtered = giantLine.push(longText) + giantLine.flush()
  assert.equal(filtered, longText.replace('DEMO_SECRET', '[REDACTADO]'))
  assert.doesNotThrow(() => readNmapReport(redactText(xml.replace('<nmaprun>', '<nmaprun args="password=DEMO_SECRET">'))))
})
test('Reportes XML y texto producen inventario; reportes incompletos fallan explícitamente', () => {
  assert.equal(readNmapReport(xml)[0].ports[0].product, 'nginx')
  assert.equal(readNmapReport(normal)[0].ports[1].state, 'closed')
  assert.deepEqual(readNmapReport('<nmaprun><runstats/></nmaprun>'), [])
  assert.throws(() => readNmapReport('<nmaprun><host>'))
  assert.throws(() => readNmapReport('<nmaprun><host></nmaprun>'))
  assert.throws(() => readNmapReport('cualquier texto'))
})
test('El resultado usa la instantánea original y se guarda una sola vez, aunque cambie el proyecto seleccionado', () => {
  const snapshot = { id: 'run', projectId: 'a', command: 'nmap -p80 192.0.2.10', targets: ['192.0.2.10'], mode: 'local', startedAt: '2026-10-01T00:00:00Z' }
  const result = { state: 'cancelled', logs: normal, date: '2026-10-01T00:01:00Z', truncated: false }
  const saved = saveExecutionResult(workspace(), snapshot, result)
  assert.equal(saved.projects[0].executions, 1)
  assert.equal(saved.projects[1].executions, 0)
  assert.equal(saved.projects[0].lastRuns[0].command, snapshot.command)
  assert.equal(saveExecutionResult(saved, snapshot, result).projects[0].executions, 1)
  assert.equal(saveExecutionResult(workspace(), snapshot, { ...result, truncated: true }).projects[0].lastRuns[0].hosts.length, 0)
  const invalid = saveExecutionResult(workspace(), snapshot, { ...result, xml: '<nmaprun><host>' }).projects[0].lastRuns[0]
  assert.equal(invalid.hosts.length, 0)
  assert.match(invalid.reportError, /incompleto/)
})
