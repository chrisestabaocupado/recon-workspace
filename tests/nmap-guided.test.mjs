import assert from 'node:assert/strict'
import test from 'node:test'
import { buildNmapArgs, parseNmapCommand } from '../src/lib/nmap-command.ts'
import { getGuidedPorts, getGuidedProtocol, setGuidedPorts, setGuidedProtocol } from '../src/lib/nmap-guided.ts'

test('Los protocolos simples reflejan TCP implícito, UDP, mixto y técnicas avanzadas', () => {
  for (const [flags, expected] of [
    ['', 'tcp'], ['-sS', 'tcp'], ['-sT', 'tcp'], ['-sU', 'udp'],
    ['-sS -sU', 'both'], ['-sA', 'advanced'], ['-sY', 'advanced'], ['-sO', 'advanced'],
  ]) assert.equal(getGuidedProtocol(parseNmapCommand(`nmap ${flags} 192.0.2.10`)), expected)
})

test('Cambiar protocolo elimina técnicas incompatibles sin perder límites ni argumentos avanzados', () => {
  const config = parseNmapCommand('nmap -n -sU -sA --scanflags SYN -sV -O --max-rate 50 -p 80,443 --future-option value 192.0.2.10')
  const original = structuredClone(config)
  for (const protocol of ['tcp', 'udp', 'both']) {
    const updated = setGuidedProtocol(config, protocol)
    assert.equal(getGuidedProtocol(updated), protocol)
    const args = buildNmapArgs(updated)
    assert.equal(args.includes('-sT'), protocol !== 'udp')
    assert.equal(args.includes('-sU'), protocol !== 'tcp')
    assert.equal(args.includes('-sA'), false)
    assert.equal(args.includes('--scanflags'), false)
    assert.equal(updated.values['max-rate'], '50')
    assert.equal(updated.values['os-detection'], true)
    assert.equal(updated.values['service-version'], true)
    assert.deepEqual(updated.unknown, config.unknown)
    assert.deepEqual(updated.targets, config.targets)
  }
  assert.deepEqual(config, original)
})

test('La selección de puertos no acumula -F, -p ni opciones top/ratio incompatibles', () => {
  const config = parseNmapCommand('nmap -sT -F --top-ports 20 --port-ratio 0.1 -p 8080 --max-rate 25 192.0.2.10')
  assert.equal(getGuidedPorts(config), 'advanced')
  for (const mode of ['common', 'default', 'all', 'custom']) {
    const next = setGuidedPorts(config, mode)
    assert.equal(getGuidedPorts(next), mode)
    assert.equal(next.values['top-ports'], undefined)
    assert.equal(next.values['port-ratio'], undefined)
    assert.equal(next.values.fast, mode === 'common' ? true : undefined)
    assert.equal(next.values.ports, mode === 'all' ? '1-65535' : mode === 'custom' ? '8080' : undefined)
    assert.equal(next.values['max-rate'], '25')
    assert.equal(next.values['connect-scan'], true)
  }
})

test('Un puerto personalizado vacío sigue siendo editable y los prefijos de protocolo se conservan', () => {
  const config = parseNmapCommand('nmap -sT -sU -p T:80,U:53 192.0.2.10')
  assert.equal(getGuidedPorts(config), 'custom')
  assert.equal(setGuidedPorts(config, 'custom').values.ports, 'T:80,U:53')
  config.values.ports = ''
  assert.equal(getGuidedPorts(config), 'custom')
})

test('Los controles no mutan la configuración y pueden salir del modo solo descubrimiento', () => {
  const config = parseNmapCommand('nmap -sn --max-rate 10 192.0.2.10')
  const updated = setGuidedProtocol(config, 'tcp')
  assert.equal(updated.values['ping-scan'], undefined)
  assert.equal(config.values['ping-scan'], true)
  assert.deepEqual(buildNmapArgs(updated), ['--max-rate', '10', '-sT', '192.0.2.10'])
})
