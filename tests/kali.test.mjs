import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { readFile } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import test from 'node:test'
import { KaliAutoVerification, kaliReady, sshSettingsSignature, executorIdentity, validateKaliDiagnostic } from '../src/lib/kali.ts'
import { KaliVerificationStore, kaliVerifications } from '../src/server/kali-access.ts'
import { validateStartInput } from '../src/server/nmap-input.ts'
import { execJsonInput, execText } from '../src/server/ssh.ts'
import { remoteHttpResponse } from '../src/server/remote-http-protocol.ts'
import { emptyWorkspace, validateWorkspace, writeActiveExecution, readActiveExecution, writeSshSettings, SSH_KEY, ACTIVE_JOB_KEY } from '../src/lib/storage.ts'
import { saveExecutionResult } from '../src/lib/execution-history.ts'
import { scopeManualResult, mergeReconResult, emptyRecon } from '../src/lib/recon.ts'

const ssh = { host: '192.0.2.20', port: 22, username: 'kali', privateKeyPath: '/synthetic/key', fingerprint: 'SHA256:synthetic', passphrase: 'synthetic-only' }
const now = Date.parse('2026-10-02T12:00:00Z')

test('Recargar comprueba automáticamente SSH completo sin duplicar intentos ni habilitar acceso antes de la respuesta', () => {
  const auto = new KaliAutoVerification()
  assert.equal(auto.claim(ssh, null, true, now), false)
  assert.equal(auto.claim(ssh, null, false, now), true)
  assert.equal(kaliReady(null, ssh, now), false)
  assert.equal(auto.claim(ssh, null, false, now), false)
  assert.equal(auto.claim(ssh, null, false, now + 5000), false)
  assert.equal(new KaliAutoVerification().claim(ssh, null, false, now), true)
})

test('La conexión automática espera datos completos y huella aceptada', () => {
  const auto = new KaliAutoVerification()
  for (const patch of [{host:''},{username:''},{privateKeyPath:''},{fingerprint:''},{port:0}])
    assert.equal(auto.claim({...ssh,...patch},null,false,now), false)
  assert.equal(auto.claim(ssh,null,false,now), true)
})

test('Renueva una vez por caducidad y conserva la invalidación al editar SSH', () => {
  const store = new KaliVerificationStore()
  const verification = {...store.issue(ssh,now),version:'synthetic',settingsSignature:sshSettingsSignature(ssh)}
  const auto = new KaliAutoVerification()
  assert.equal(auto.claim(ssh,verification,false,now), false)
  const expires = Date.parse(verification.expiresAt)
  assert.equal(auto.claim({...ssh,username:'changed'},verification,false,expires), false)
  assert.equal(auto.claim(ssh,verification,false,expires), true)
  assert.equal(auto.claim(ssh,verification,false,expires), false)
  assert.equal(auto.claim(ssh,null,false,expires+5000), false)
  const renewed = {...store.issue(ssh,expires),version:'synthetic',settingsSignature:sshSettingsSignature(ssh)}
  assert.equal(auto.claim(ssh,renewed,false,expires), false)
  assert.equal(auto.claim(ssh,renewed,false,Date.parse(renewed.expiresAt)), true)
})

test('El backend impide ejecución local, conexiones sin verificar y tokens inventados', () => {
  const store = new KaliVerificationStore()
  const verified = store.issue(ssh, now)
  const access = { mode: 'ssh', ssh, kaliToken: verified.token }
  for (const mode of ['local', undefined, 'other']) assert.throws(() => store.require({ ...access, mode }, now), /local|Kali/)
  for (const kaliToken of [undefined, '', 'a'.repeat(36), '00000000-0000-4000-8000-000000000000']) assert.throws(() => store.require({ ...access, kaliToken }, now), /Comprueba|verificación/)
  assert.deepEqual(store.require(access, now), access)
  assert.notEqual(store.require(access, now).ssh, ssh)
})

test('La verificación se vincula a todos los campos y caduca; reiniciar exige comprobar Kali otra vez', () => {
  const store = new KaliVerificationStore()
  const verified = store.issue(ssh, now)
  const access = { mode: 'ssh', ssh, kaliToken: verified.token }
  for (const patch of [{ host: '192.0.2.21' }, { port: 2222 }, { username: 'other' }, { privateKeyPath: '/other' }, { fingerprint: 'SHA256:changed' }, { passphrase: 'changed' }]) assert.throws(() => store.require({ ...access, ssh: { ...ssh, ...patch } }, now), /verificación/)
  assert.throws(() => store.require(access, Date.parse(verified.expiresAt)), /verificación/)
  assert.throws(() => new KaliVerificationStore().require(access, now), /verificación/)
  assert.deepEqual(Object.keys(verified.executor).sort(), ['fingerprint', 'host', 'port', 'username'])
})

test('Nmap usa la validación remota incluso para diagnósticos y conserva los guardas de alcance', () => {
  const input = { args: ['--version'], projectId: 'synthetic', authorized: true, timeoutSeconds: 10 }
  for (const mode of ['local', undefined, 'ssh']) assert.throws(() => validateStartInput({ ...input, mode, ssh }))
  const verified = kaliVerifications.issue(ssh)
  const accepted = validateStartInput({ ...input, mode: 'ssh', ssh, kaliToken: verified.token })
  assert.equal(accepted.mode, 'ssh')
  assert.notEqual(accepted.args, input.args)
  assert.throws(() => validateStartInput({ ...accepted, args: ['192.0.2.10'] }), /plan/)
  assert.throws(() => validateStartInput({ ...accepted, authorized: false }), /autorizado/)
})

test('El estado compartido de la UI queda inválido al cambiar campos, recargar o caducar', () => {
  const store = new KaliVerificationStore()
  const verification = { ...store.issue(ssh, now), version: 'synthetic', settingsSignature: sshSettingsSignature(ssh) }
  assert.equal(kaliReady(verification, ssh, now), true)
  assert.equal(kaliReady(null, ssh, now), false)
  assert.equal(kaliReady(verification, { ...ssh, passphrase: '' }, now), false)
  assert.equal(kaliReady(verification, { ...ssh, host: '192.0.2.21' }, now), false)
  assert.equal(kaliReady(verification, ssh, Date.parse(verification.expiresAt)), false)
  assert.equal(kaliReady({ ...verification, expiresAt: 'invalid' }, ssh, now), false)
})

test('El diagnóstico exige Kali Linux, Node moderno y Nmap disponible', () => {
  const info = { platform: 'linux', distro: 'kali', node: 'v22.12.0', nmap: 'Nmap version 7.95' }
  assert.match(validateKaliDiagnostic(info), /Kali Linux/)
  for (const patch of [{ platform: 'win32' }, { distro: 'debian' }, { node: 'v20.0.0' }, { node: '' }, { nmap: '' }]) assert.throws(() => validateKaliDiagnostic({ ...info, ...patch }))
})

function fakeConnection(onInput) {
  const connection = new EventEmitter()
  const stream = new EventEmitter()
  stream.stderr = new EventEmitter()
  stream.close = () => { stream.closed = true; stream.emit('close', null) }
  stream.end = (data) => queueMicrotask(() => onInput(data, stream))
  connection.exec = (command, callback) => { connection.command = command; callback(null, stream) }
  return { connection, stream }
}

test('El transporte SSH envía datos por stdin, conserva UTF-8 y nunca inserta el payload en shell', async () => {
  const payload = { url: "https://synthetic.invalid/?q=';echo injected", timeoutMs: 5000 }
  const { connection } = fakeConnection((input, stream) => {
    assert.deepEqual(JSON.parse(input), payload)
    const bytes = Buffer.from(JSON.stringify({ value: 'évidencia' }))
    for (const byte of bytes) stream.emit('data', Buffer.from([byte]))
    stream.emit('close', 0)
  })
  assert.deepEqual(await execJsonInput(connection, 'console.log("fixed script")', payload, new AbortController().signal), { value: 'évidencia' })
  assert.ok(!connection.command.includes('injected'))
  assert.equal(connection.listenerCount('close'), 0)
})

test('El transporte rechaza desconexión, salida desconocida, JSON inválido y respuestas excesivas', async () => {
  for (const run of [(_, s) => s.emit('close', null), (_, s) => { s.emit('data', Buffer.from('invalid')); s.emit('close', 0) }, (_, s) => { s.emit('data', Buffer.alloc(100)); s.emit('close', 0) }]) {
    const { connection } = fakeConnection(run)
    await assert.rejects(execJsonInput(connection, 'fixed', {}, new AbortController().signal, 20))
  }
  const disconnected = fakeConnection(() => disconnected.connection.emit('close'))
  await assert.rejects(execJsonInput(disconnected.connection, 'fixed', {}, new AbortController().signal), /perdió SSH/)
  const controller = new AbortController()
  const aborted = fakeConnection(() => controller.abort())
  await assert.rejects(execJsonInput(aborted.connection, 'fixed', {}, controller.signal), /cancelada/)
  assert.equal(aborted.stream.closed, true)
  const textController = new AbortController()
  const text = fakeConnection(() => textController.abort())
  const diagnostic = execText(text.connection, 'fixed diagnostic', textController.signal)
  queueMicrotask(() => textController.abort())
  await assert.rejects(diagnostic, /agotó/)
})

test('El protocolo HTTPS remoto valida tipo, tamaño y estado conservando errores HTTP', async () => {
  const response = remoteHttpResponse({ status: 429, contentType: 'application/json', body: Buffer.from('{"error":"limit"}').toString('base64') })
  assert.equal(response.status, 429)
  assert.deepEqual(await response.json(), { error: 'limit' })
  for (const value of [null, { status: 200, contentType: 'application/json', body: '$bad' }, { status: 100, contentType: '', body: '' }, { status: 200, contentType: 'x'.repeat(256), body: '' }, { status: 200, contentType: '', body: 'AAAA'.repeat(1048577) }]) assert.throws(() => remoteHttpResponse(value))
  assert.equal(await remoteHttpResponse({ status: 204, contentType: '', body: '' }).text(), '')
})

async function runRemoteHttp(request, responseBytes = 2) {
  const script = await readFile(new URL('../src/server/remote-http.mjs', import.meta.url), 'utf8')
  // Fixed local simulation of the code uploaded to Kali. It cannot make network requests.
  const mocked = `globalThis.fetch = async (url, init) => { if (init.redirect !== 'error' || init.credentials !== 'omit' || !init.signal) throw new Error('unsafe HTTP policy'); return new Response('x'.repeat(${responseBytes}), {status:429, headers:{'content-type':'application/json'}}); };\n`
  const child = spawn(process.execPath, ['--input-type=module', '-e', mocked + script], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] })
  let output = ''; let error = ''
  child.stdout.on('data', (data) => { output += data })
  child.stderr.on('data', (data) => { error += data })
  child.stdin.end(JSON.stringify(request))
  return new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code) => resolve({ code, output, error })) })
}

test('El programa subido a Kali limita HTTPS y tamaño sin hacer solicitudes reales en las pruebas', async () => {
  const request = { url: 'https://synthetic.invalid/query', timeoutMs: 5000 }
  const result = await runRemoteHttp(request)
  assert.equal(result.code, 0)
  assert.equal(JSON.parse(result.output).status, 429)
  for (const patch of [{ url: 'http://synthetic.invalid/' }, { url: 'https://user:pass@synthetic.invalid/' }, { url: 'https://synthetic.invalid:8443/' }, { timeoutMs: 60001 }]) assert.notEqual((await runRemoteHttp({ ...request, ...patch })).code, 0)
  assert.match((await runRemoteHttp(request, 3 * 1024 * 1024 + 1)).error, /supera 3 MB/)
})

test('Historial y evidencias guardan la identidad SSH sin token, frase ni clave', () => {
  const executor = { ...executorIdentity(ssh), privateKeyPath: ssh.privateKeyPath, passphrase: ssh.passphrase, kaliToken: 'synthetic-token' }
  const snapshot = { id: 'run', projectId: 'p', command: 'nmap --version', targets: [], mode: 'ssh', startedAt: new Date(now).toISOString(), executor }
  const workspace = { ...emptyWorkspace(), selectedProjectId: 'p', projects: [{ id: 'p', name: 'Synthetic', scope: '', createdAt: new Date(now).toISOString(), targets: [], executions: 0 }] }
  const saved = validateWorkspace(saveExecutionResult(workspace, snapshot, { state: 'completed', logs: '', date: new Date(now).toISOString(), truncated: false }))
  assert.deepEqual(saved.projects[0].lastRuns[0].executor, executorIdentity(ssh))
  let nextId = 0
  const recon = mergeReconResult(emptyRecon(), { ...scopeManualResult('synthetic.invalid', 'Synthetic', '', new Date(now).toISOString()), executor }, '', () => `evidence-${++nextId}`)
  assert.deepEqual(recon.evidence[0].executor, executorIdentity(ssh))
  const values = new Map()
  const originalWindow = globalThis.window
  globalThis.window = { localStorage: { setItem: (key, value) => values.set(key, value), getItem: (key) => values.get(key) ?? null } }
  try {
    assert.equal(writeActiveExecution(snapshot), true)
    assert.deepEqual(readActiveExecution().executor, executorIdentity(ssh))
    assert.equal(writeSshSettings(ssh), true)
    for (const key of [ACTIVE_JOB_KEY, SSH_KEY]) for (const secret of ['synthetic-only', 'synthetic-token']) assert.ok(!values.get(key).includes(secret))
    assert.ok(!values.get(ACTIVE_JOB_KEY).includes('/synthetic/key'))
    assert.ok(!JSON.stringify(saved).includes('synthetic-only'))
  } finally { globalThis.window = originalWindow }
})
