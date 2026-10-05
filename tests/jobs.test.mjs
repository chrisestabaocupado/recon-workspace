import assert from 'node:assert/strict'
import test from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { JobManager } from '../src/server/job-manager.ts'

const tick = () => new Promise((resolve) => setImmediate(resolve))
const input = (args = ['-sT', '192.0.2.10']) => ({ projectId: 'a', mode: 'local', args, timeoutMs: 60000 })
function fixture() {
  const messages = []
  let onEvent
  let onClose
  let closed = false
  const launch = async (_signal, event, close) => {
    onEvent = event
    onClose = close
    return { send: (message) => { messages.push(message); if (message.type === 'start') onEvent({ type: 'ready', pid: 1 }) }, close: () => { closed = true } }
  }
  return { launch, messages, event: (event) => onEvent(event), disconnect: () => onClose('Conexión perdida'), closed: () => closed }
}
test('Cancelar durante el inicio impide enviar start y no lanza el proceso', async () => {
  const manager = new JobManager()
  let ready
  const messages = []
  const job = manager.start(input(), () => new Promise((resolve) => { ready = resolve }))
  assert.equal(manager.get(job.id).state, 'starting')
  manager.cancel(job.id)
  assert.equal(manager.get(job.id).state, 'cancelling')
  ready({ send: (message) => messages.push(message), close: () => {} })
  await tick()
  assert.equal(manager.get(job.id).state, 'cancelled')
  assert.equal(messages.length, 0)
})
test('Cancelar exige exit confirmado; el estado final y los logs permanecen consultables', async () => {
  const manager = new JobManager()
  const fake = fixture()
  const job = manager.start(input(), fake.launch)
  await tick()
  fake.event({ type: 'log', stream: 'stdout', data: 'salida\n' })
  manager.cancel(job.id)
  assert.equal(manager.get(job.id).state, 'cancelling')
  assert.equal(fake.messages.at(-1).type, 'cancel')
  fake.event({ type: 'exit', code: null, signal: 'SIGTERM', reason: 'cancelled' })
  assert.equal(manager.get(job.id).state, 'cancelled')
  assert.equal(manager.get(job.id).logs, 'salida\n')
  assert.ok(fake.closed())
})
test('Una conexión perdida no informa cancelación ni finalización exitosa', async () => {
  const manager = new JobManager()
  const fake = fixture()
  const job = manager.start(input(), fake.launch)
  await tick()
  fake.disconnect()
  assert.equal(manager.get(job.id).state, 'unknown')
  assert.match(manager.get(job.id).error, /perdida/)
})
test('La cancelación sin acuse termina como desconocida', async () => {
  const manager = new JobManager(1000, 20)
  const fake = fixture()
  const job = manager.start(input(), fake.launch)
  await tick()
  manager.cancel(job.id)
  await delay(35)
  assert.equal(manager.get(job.id).state, 'unknown')
})
test('El timeout solicita cierre y conserva timed_out tras confirmación', async () => {
  const manager = new JobManager(1000, 1000)
  const fake = fixture()
  const job = manager.start({ ...input(), timeoutMs: 20 }, fake.launch)
  await delay(35)
  assert.equal(manager.get(job.id).state, 'cancelling')
  assert.equal(fake.messages.at(-1).reason, 'timed_out')
  fake.event({ type: 'exit', code: null, reason: 'timed_out' })
  assert.equal(manager.get(job.id).state, 'timed_out')
})
test('Metadatos y argv se fijan al iniciar; logs y artefactos se depuran antes de exponerlos', async () => {
  const manager = new JobManager()
  const fake = fixture()
  const request = input(['--script-args', 'smbpassword=DEMO_SECRET', '192.0.2.10'])
  const job = manager.start(request, fake.launch)
  request.args[1] = 'otra-cosa'
  request.projectId = 'b'
  await tick()
  assert.equal(fake.messages[0].args[1], 'smbpassword=DEMO_SECRET')
  fake.event({ type: 'log', stream: 'stdout', data: 'password=DEMO_' })
  fake.event({ type: 'log', stream: 'stdout', data: 'SECRET\n' })
  fake.event({ type: 'artifact', filename: 'report.xml', data: '<nmaprun args="smbpassword=DEMO_SECRET"/>' })
  fake.event({ type: 'exit', code: 0 })
  const snapshot = manager.get(job.id)
  assert.equal(snapshot.projectId, 'a')
  assert.ok(!JSON.stringify(snapshot).includes('DEMO_SECRET'))
  assert.ok(!manager.artifact(job.id).text.includes('DEMO_SECRET'))
})
test('Logs truncados incluyen gap y offsets; recuperar desde cero no duplica texto', async () => {
  const manager = new JobManager(64)
  const fake = fixture()
  const job = manager.start(input(), fake.launch)
  await tick()
  fake.event({ type: 'log', stream: 'stdout', data: 'x'.repeat(100) + '\n' })
  const first = manager.get(job.id, 0)
  assert.equal(first.logs.length, 64)
  assert.equal(first.truncated, true)
  assert.equal(first.gap, true)
  assert.equal(first.offset, 101)
  fake.event({ type: 'log', stream: 'stdout', data: 'final\n' })
  assert.equal(manager.get(job.id, first.offset).logs, 'final\n')
  fake.event({ type: 'exit', code: 0 })
  assert.equal(manager.get(job.id, 0).logs.length, 64)
  assert.equal(manager.get('missing').found, false)
})
