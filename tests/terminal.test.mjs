import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { KaliVerificationStore } from '../src/server/kali-access.ts';
import { terminalReadInput, terminalResizeInput, terminalSessionInput, terminalStartInput, terminalWriteInput } from '../src/server/terminal-input.ts';
import { TerminalManager } from '../src/server/terminal-manager.ts';
import { openSshTerminal } from '../src/server/terminal-ssh.ts';

const ssh = { host: '192.0.2.20', port: 22, username: 'kali', privateKeyPath: '/synthetic/key', fingerprint: 'SHA256:synthetic' };
const size = { cols: 100, rows: 30 };
const capability = { id: '00000000-0000-4000-8000-000000000000', secret: 'a'.repeat(64) };

function fakeTransport() {
  const input = [], sizes = [];
  let closes = 0;
  return { input, sizes, get closes() { return closes; }, write: text => input.push(text), resize: value => sizes.push(value), close: () => closes++ };
}

test('La terminal requiere la misma configuración SSH verificada, nunca ejecución local ni otra huella', () => {
  const store = new KaliVerificationStore();
  const verification = store.issue(ssh);
  const request = { mode: 'ssh', ssh, kaliToken: verification.token, ...size };
  assert.deepEqual(terminalStartInput(request, store).ssh, ssh);
  for (const patch of [{ mode: 'local' }, { kaliToken: capability.id }, { ssh: { ...ssh, host: 'other.test' } }, { ssh: { ...ssh, fingerprint: 'SHA256:other' } }, { ssh: { ...ssh, passphrase: 'changed' } }]) {
    assert.throws(() => terminalStartInput({ ...request, ...patch }, store));
  }
  const expired = store.issue(ssh, Date.now() - 16 * 60 * 1000);
  assert.throws(() => terminalStartInput({ ...request, kaliToken: expired.token }, store), /caducó/);
});

test('Las peticiones validan capacidad, tamaño, offset y entrada, pero permiten teclas de control', () => {
  assert.deepEqual(terminalSessionInput(capability), capability);
  assert.equal(terminalWriteInput({ ...capability, input: '\x03\x1b[A\t\r' }).input, '\x03\x1b[A\t\r');
  assert.deepEqual(terminalResizeInput({ ...capability, ...size }), { ...capability, ...size });
  for (const input of ['', 'x'.repeat(8193), null, {}]) assert.throws(() => terminalWriteInput({ ...capability, input }));
  for (const offset of [-1, 1.5, Infinity, '0', undefined]) assert.throws(() => terminalReadInput({ ...capability, offset }));
  for (const patch of [{ cols: 0 }, { cols: 501 }, { rows: 201 }, { rows: 1.2 }, { cols: '100' }]) assert.throws(() => terminalResizeInput({ ...capability, ...size, ...patch }));
  for (const patch of [{ secret: '' }, { secret: 'b'.repeat(63) }, { id: '../../file' }]) assert.throws(() => terminalSessionInput({ ...capability, ...patch }));
});

test('Cada sesión tiene capacidad propia; entrada y tamaño llegan solo a su transporte', async () => {
  const manager = new TerminalManager();
  const firstTransport = fakeTransport(), secondTransport = fakeTransport();
  let output, close;
  const first = await manager.start(async (_signal, emit, done) => { output = emit; close = done; return firstTransport; });
  const second = await manager.start(async () => secondTransport);
  assert.notEqual(first.secret, second.secret);
  output('kali$ ');
  assert.throws(() => manager.read({ ...first, secret: second.secret }, 0), /no existe/);
  assert.throws(() => manager.write({ ...first, secret: second.secret }, 'whoami\r'), /no existe/);
  assert.throws(() => manager.close({ ...first, secret: second.secret }), /no existe/);
  manager.write(first, 'whoami\r'); manager.write(first, '\x03'); manager.resize(first, size);
  assert.deepEqual(firstTransport.input, ['whoami\r', '\x03']);
  assert.deepEqual(firstTransport.sizes, [size]); assert.deepEqual(secondTransport.input, []);
  const frame = manager.read(first, 0);
  assert.equal(frame.data, 'kali$ ');
  assert.deepEqual(manager.read(first, 0), frame); // Retrying a read does not consume output.
  assert.equal(manager.read(first, frame.offset).data, '');
  assert.throws(() => manager.read(first, frame.offset + 1), /rango/);
  close('El shell remoto se cerró.');
  assert.equal(manager.read(first, 0).state, 'closed');
  assert.throws(() => manager.write(first, 'id\r'), /desconectada/);
  manager.close(first); manager.close(second);
  assert.throws(() => manager.read(first, 0), /no existe/);
  assert.equal(firstTransport.closes, 1); assert.equal(secondTransport.closes, 1);
});

test('La salida en memoria está acotada e informa de truncamiento sin romper caracteres Unicode', async () => {
  const manager = new TerminalManager();
  let output;
  const session = await manager.start(async (_signal, emit) => { output = emit; return fakeTransport(); });
  output('😀'.repeat(140000) + 'fin');
  const frame = manager.read(session, 0);
  assert.equal(frame.truncated, true); assert.ok(frame.data.length <= 256 * 1024);
  assert.ok(!/^[\uDC00-\uDFFF]/u.test(frame.data));
  assert.equal(frame.offset, 280003); assert.ok(frame.data.endsWith('fin'));
  assert.equal(manager.read(session, frame.offset).truncated, false);
  manager.close(session);
});

test('La capacidad máxima incluye conexiones en apertura y los fallos liberan la plaza', async () => {
  const manager = new TerminalManager();
  await assert.rejects(manager.start(async () => { throw new Error('SSH unavailable'); }), /SSH unavailable/);
  const ready = [];
  const pending = Array.from({ length: 4 }, () => manager.start(() => new Promise(resolve => ready.push(resolve))));
  await assert.rejects(manager.start(async () => fakeTransport()), /demasiadas/);
  for (const resolve of ready) resolve(fakeTransport());
  const sessions = await Promise.all(pending);
  for (const session of sessions) manager.close(session);
  const next = await manager.start(async () => fakeTransport()); manager.close(next);
});

test('Una pestaña desaparecida libera SSH y descarta su salida al caducar el heartbeat', async () => {
  const manager = new TerminalManager(20), transport = fakeTransport();
  let signal;
  const session = await manager.start(async value => { signal = value; return transport; });
  await delay(50);
  assert.equal(signal.aborted, true); assert.equal(transport.closes, 1);
  assert.throws(() => manager.read(session, 0), /no existe/);
});

function fakeSsh() {
  const connection = new EventEmitter(), stream = new EventEmitter();
  const inputs = [], windows = [];
  stream.stderr = new EventEmitter(); stream.writableLength = 0;
  stream.write = input => inputs.push(input); stream.setWindow = (...args) => windows.push(args);
  stream.close = () => { stream.destroyed = true; };
  connection.end = () => { connection.ended = true; };
  connection.shell = (options, callback) => { connection.options = options; callback(null, stream); };
  return { connection, stream, inputs, windows };
}

test('El transporte solicita un PTY real, preserva UTF-8, transmite teclas y redimensiona sin shell local', async () => {
  const { connection, stream, inputs, windows } = fakeSsh();
  const output = [], closed = [], controller = new AbortController();
  const transport = await openSshTerminal(connection, size, controller.signal, text => output.push(text), text => closed.push(text));
  assert.deepEqual(connection.options, { term: 'xterm-256color', ...size });
  const bytes = Buffer.from('Kali · español 😀');
  for (const byte of bytes) stream.emit('data', Buffer.from([byte]));
  stream.stderr.emit('data', Buffer.from('error'));
  assert.equal(output.join(''), 'Kali · español 😀error');
  transport.write('pwd\r'); transport.write('\x03'); transport.resize({ cols: 120, rows: 40 });
  assert.deepEqual(inputs, ['pwd\r', '\x03']); assert.deepEqual(windows, [[40, 120, 0, 0]]);
  stream.writableLength = 65537;
  assert.throws(() => transport.write('more input'), /no está procesando/);
  assert.deepEqual(inputs, ['pwd\r', '\x03']);
  controller.abort();
  assert.equal(connection.ended, true); assert.equal(stream.destroyed, true); assert.equal(closed.length, 1);
  assert.throws(() => transport.write('id\r'), /desconectada/);
});

test('El transporte distingue cierre de shell y pérdida de SSH; no reintenta comandos', async () => {
  for (const event of ['close', 'error', 'shell-close']) {
    const { connection, stream, inputs } = fakeSsh();
    const closed = [];
    const transport = await openSshTerminal(connection, size, new AbortController().signal, () => {}, message => closed.push(message));
    if (event === 'shell-close') stream.emit('close');
    else connection.emit(event, new Error('synthetic'));
    assert.equal(closed.length, 1); assert.equal(connection.ended, true);
    assert.match(closed[0], event === 'shell-close' ? /shell remoto/ : /perdió/);
    assert.deepEqual(inputs, []); transport.close(); assert.equal(closed.length, 1);
  }
});

test('Un shell que llega después de cancelar también se cierra', async () => {
  const { connection, stream } = fakeSsh();
  let ready;
  connection.shell = (_options, callback) => { ready = callback; };
  const controller = new AbortController();
  const pending = openSshTerminal(connection, size, controller.signal, () => {}, () => {});
  const rejected = assert.rejects(pending, /cerrada/);
  controller.abort(); ready(null, stream); await rejected;
  assert.equal(stream.destroyed, true); assert.equal(connection.ended, true);
});
