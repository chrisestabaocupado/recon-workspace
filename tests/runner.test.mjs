import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { spawn } from 'node:child_process'
import { copyFile, link, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'

let fixtureDirectory
before(async () => {
  fixtureDirectory = await mkdtemp(path.join(tmpdir(), 'enumeration-runner-'))
  const binary = path.join(fixtureDirectory, process.platform === 'win32' ? 'nmap.exe' : 'nmap')
  try { await link(process.execPath, binary) } catch { await copyFile(process.execPath, binary) }
})
after(async () => {
  const resolved = path.resolve(fixtureDirectory)
  if (!resolved.startsWith(path.resolve(tmpdir()) + path.sep) || !path.basename(resolved).startsWith('enumeration-runner-')) throw new Error('Ruta temporal inesperada; no se elimina.')
  await rm(resolved, { recursive: true, force: true })
})
async function runFixture({ mode = 'complete', timeoutMs = 60000, args } = {}) {
  const runner = spawn(process.execPath, [fileURLToPath(new URL('../src/server/runner.mjs', import.meta.url))], { env: { ...process.env, PATH: fixtureDirectory + path.delimiter + process.env.PATH }, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true })
  const events = []
  const lines = createInterface({ input: runner.stdout })
  let errors = ''
  runner.stderr.on('data', (data) => { errors += data.toString() })
  return await new Promise((resolve, reject) => {
    const guard = setTimeout(() => { runner.kill('SIGTERM'); reject(new Error('El runner simulado no terminó: ' + errors)) }, 15000)
    lines.on('line', (line) => {
      const event = JSON.parse(line)
      events.push(event)
      if (event.type === 'ready' && mode === 'cancel') runner.stdin.write(JSON.stringify({ type: 'cancel' }) + '\n')
      if (event.type === 'ready' && mode === 'disconnect') runner.stdin.end()
    })
    runner.once('error', (error) => { clearTimeout(guard); reject(error) })
    runner.once('exit', () => { clearTimeout(guard); resolve(events) })
    const script = mode === 'complete' ? "process.stdout.write('resultado simulado\\n')" : 'setInterval(() => {}, 1000)'
    // PATH is scoped to this fixture. The fake nmap is Node; no network scan occurs.
    runner.stdin.write(JSON.stringify({ type: 'start', tool: 'nmap', args: args ?? ['-e', script], timeoutMs }) + '\n')
  })
}
test('Runner completa un proceso controlado y entrega stdout', async () => {
  const events = await runFixture()
  assert.equal(events.at(-1).type, 'exit')
  assert.equal(events.at(-1).code, 0)
  assert.ok(events.some((event) => event.type === 'log' && event.data.includes('resultado simulado')))
})
test('Runner confirma cancelación después de detener el hijo', async () => {
  const events = await runFixture({ mode: 'cancel' })
  assert.equal(events.at(-1).reason, 'cancelled')
  const pid = events.find((event) => event.type === 'ready').pid
  assert.throws(() => process.kill(pid, 0))
})
test('Cerrar el canal de entrada cancela el hijo en vez de dejarlo activo', async () => {
  const events = await runFixture({ mode: 'disconnect' })
  assert.equal(events.at(-1).reason, 'cancelled')
  assert.throws(() => process.kill(events.find((event) => event.type === 'ready').pid, 0))
})
test('Runner aplica un timeout y confirma el cierre del hijo', async () => {
  const events = await runFixture({ mode: 'timeout', timeoutMs: 100 })
  assert.equal(events.at(-1).reason, 'timed_out')
  assert.throws(() => process.kill(events.find((event) => event.type === 'ready').pid, 0))
})

const fixtureXml = '<nmaprun><host><status state="up"/><hostnames><hostname name="máquina"/></hostnames></host></nmaprun>'
test('XML stdout conserva UTF-8 dividido entre chunks y se entrega antes de exit', async () => {
  const script = path.join(fixtureDirectory, 'xml-stdout.cjs')
  await writeFile(script, `const xml = Buffer.from(${JSON.stringify(fixtureXml)}); const split = xml.indexOf(Buffer.from('á')) + 1; process.stdout.write(xml.subarray(0, split)); setTimeout(() => process.stdout.write(xml.subarray(split)), 30);`)
  const events = await runFixture({ args: [script, '-oX', '-'] })
  assert.equal(events.find((event) => event.type === 'artifact')?.data, fixtureXml)
  assert.equal(events.at(-1).type, 'exit')
  assert.equal(events.filter((event) => event.type === 'log').map((event) => event.data).join(''), fixtureXml)
})
test('XML en archivo se recoge íntegro sin depender de logs', async () => {
  const script = path.join(fixtureDirectory, 'xml-file.cjs')
  const output = path.join(fixtureDirectory, 'report.xml')
  await writeFile(script, `require('node:fs').writeFileSync(process.argv[3], ${JSON.stringify(fixtureXml)})`)
  const events = await runFixture({ args: [script, '-oX', output] })
  assert.equal(events.find((event) => event.type === 'artifact')?.data, fixtureXml)
  assert.equal(events.at(-1).code, 0)
})
test('Los argumentos después de -- no se interpretan como flags de artefactos', async () => {
  const events = await runFixture({ args: ['-e', "process.stdout.write('resultado')", '--', '-oX', '-'] })
  assert.equal(events.at(-1).code, 0)
  assert.equal(events.some((event) => event.type === 'artifact'), false)
})
