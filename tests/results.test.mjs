import assert from 'node:assert/strict'
import test from 'node:test'
import { mergeObservedHosts, readNmapReport } from '../src/lib/results.ts'

test('XML agrupa la IP repetida y une puertos sin duplicar protocolos', () => {
  const host = (ports) => `<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports>${ports}</ports></host>`
  const port = (id, protocol = 'tcp') => `<port protocol="${protocol}" portid="${id}"><state state="open"/><service name="test"/></port>`
  const report = `<nmaprun>${host(port(25) + port(443))}${host(port(25) + port(53, 'udp'))}</nmaprun>`
  const hosts = readNmapReport(report)
  assert.equal(hosts.length, 1)
  assert.deepEqual(hosts[0].ports.map(p => `${p.port}/${p.protocol}`), ['25/tcp', '53/udp', '443/tcp'])
})

test('Texto agrupa IP y dominio resuelto conservando hosts distintos', () => {
  const hosts = readNmapReport('Nmap scan report for lab.test (192.0.2.10)\nHost is up.\n80/tcp open http nginx\nNmap scan report for 192.0.2.10\nHost is up.\n443/tcp open https\nNmap scan report for 192.0.2.11\nHost is up.\n80/tcp open http\nNmap done:')
  assert.equal(hosts.length, 2)
  assert.equal(hosts[0].hostname, 'lab.test')
  assert.equal(hosts[0].ports.length, 2)
})

test('Inventarios antiguos se agrupan sin mutarlos; prevalece el último estado observado', () => {
  const port = { port: 80, protocol: 'tcp', state: 'open', service: 'http', product: 'nginx', version: '1' }
  const original = [{ address: '192.0.2.10', status: 'up', ports: [port] }, { address: '192.0.2.10', ports: [{ ...port, state: 'closed', service: 'unknown', product: undefined, version: undefined }, { ...port, protocol: 'udp' }] }]
  const snapshot = structuredClone(original)
  const merged = mergeObservedHosts(original)
  assert.equal(merged.length, 1)
  assert.equal(merged[0].ports.length, 2)
  assert.equal(merged[0].ports[0].state, 'closed')
  assert.equal(merged[0].ports[0].product, undefined)
  assert.equal(merged[0].ports[0].service, 'unknown')
  assert.deepEqual(original, snapshot)
  assert.deepEqual(mergeObservedHosts(merged), merged)
})
