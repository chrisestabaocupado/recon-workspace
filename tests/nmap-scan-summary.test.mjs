import assert from 'node:assert/strict'
import test from 'node:test'
import { buildNmapCommand, emptyConfigWithProfile, getNmapScanSummary } from '../src/lib/nmap-command.ts'
import { readNmapReport } from '../src/lib/results.ts'

test('El escaneo UDP de la captura no descarta HTTP en TCP ni inventa puertos', () => {
  const summary = getNmapScanSummary('nmap -n -sU -F -sV -O --max-rate 100 192.0.2.10/32')
  assert.equal(summary.label, 'Protocolos solicitados: UDP')
  assert.match(summary.warning, /no comprueba puertos TCP/)
  assert.match(summary.warning, /80\/tcp/)
  const hosts = readNmapReport('Nmap scan report for 192.0.2.10\nHost is up.\nAll 100 scanned ports on 192.0.2.10 are in ignored states.\nNot shown: 100 closed udp ports (port-unreach)\nNmap done:')
  assert.deepEqual(hosts[0].ports, [])
})

test('Distingue TCP implícito, explícito y combinado con UDP', () => {
  for (const flags of ['', '-sV -O', '-sT', '-sS', '-sA']) {
    const summary = getNmapScanSummary(`nmap ${flags} 192.0.2.10`)
    assert.equal(summary.label, 'Protocolos solicitados: TCP')
    assert.equal(summary.warning, undefined)
  }
  const mixed = getNmapScanSummary('nmap -sT -sU -sV 192.0.2.10')
  assert.equal(mixed.label, 'Protocolos solicitados: TCP + UDP')
  assert.equal(mixed.warning, undefined)
})

test('No confunde descubrimiento, SCTP o protocolos IP con enumeración TCP', () => {
  for (const flag of ['-sn', '-sL']) {
    const summary = getNmapScanSummary(`nmap ${flag} 192.0.2.10`)
    assert.equal(summary.label, 'Sin enumeración de puertos')
    assert.match(summary.warning, /no enumera puertos/)
  }
  assert.equal(getNmapScanSummary('nmap -sY 192.0.2.10').label, 'Protocolos solicitados: SCTP')
  assert.equal(getNmapScanSummary('nmap -sO 192.0.2.10').label, 'Protocolos IP, no puertos TCP/UDP')
  for (const command of ['nmap [reporte importado]', 'nmap -p', 'nmap --future-option value 192.0.2.10']) {
    assert.equal(getNmapScanSummary(command), null)
  }
})

test('El perfil web comprueba 80 y 443 por TCP, conserva estados cerrados y no ejecuta nada', () => {
  const config = emptyConfigWithProfile('web')
  config.targets = ['192.0.2.10']
  assert.equal(buildNmapCommand(config), 'nmap -sT -p 80,443 -sV 192.0.2.10')
  assert.equal(config.values['udp-scan'], undefined)
  assert.equal(config.values.fast, undefined)
  assert.equal(config.values['open-only'], undefined)
})
