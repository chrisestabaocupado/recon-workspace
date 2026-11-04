import assert from 'node:assert/strict';
import test from 'node:test';
import { terminalOutput } from '../src/lib/terminal-output.ts';

function buffer(lines) {
  return {
    length: lines.length,
    getLine(index) {
      const line = lines[index];
      if (!line) return undefined;
      return {
        isWrapped: line.wrapped ?? false,
        translateToString: trimRight => trimRight ? line.text.trimEnd() : line.text,
      };
    },
  };
}

test('Copia todo el historial y la pantalla como texto, conservando líneas en blanco internas y Unicode', () => {
  assert.equal(terminalOutput(buffer([
    { text: 'kali$ whoami   ' },
    { text: 'kali' },
    { text: '' },
    { text: 'Español 😀' },
    { text: '' },
    { text: '' },
  ])), 'kali$ whoami\nkali\n\nEspañol 😀');
});

test('Une líneas partidas por el ancho sin perder espacios en el punto de corte', () => {
  assert.equal(terminalOutput(buffer([
    { text: 'curl ' },
    { text: 'https://', wrapped: true },
    { text: 'example.com   ', wrapped: true },
    { text: 'HTTP/1.1 200 OK' },
  ])), 'curl https://example.com\nHTTP/1.1 200 OK');
});

test('Un buffer vacío o limpio no añade líneas vacías al portapapeles', () => {
  assert.equal(terminalOutput(buffer([])), '');
  assert.equal(terminalOutput(buffer([{ text: '   ' }, { text: '' }])), '');
  assert.equal(terminalOutput(buffer([{ text: 'kali$ ' }, { text: '' }])), 'kali$');
});
