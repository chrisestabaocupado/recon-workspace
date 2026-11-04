import type { TerminalSession, TerminalSize } from "../lib/terminal.ts";
import {
	type KaliVerificationStore,
	kaliVerifications,
} from "./kali-access.ts";

function record(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error("Solicitud de terminal inválida.");
	return value as Record<string, unknown>;
}

export function terminalSize(value: unknown): TerminalSize {
	const { cols, rows } = record(value);
	if (
		!Number.isInteger(cols) ||
		!Number.isInteger(rows) ||
		Number(cols) < 2 ||
		Number(cols) > 500 ||
		Number(rows) < 1 ||
		Number(rows) > 200
	)
		throw new Error("Dimensiones de terminal inválidas.");
	return { cols: Number(cols), rows: Number(rows) };
}

export function terminalStartInput(
	value: unknown,
	verifications: KaliVerificationStore = kaliVerifications,
) {
	const input = record(value);
	return { ...verifications.require(input), ...terminalSize(input) };
}

export function terminalSessionInput(value: unknown): TerminalSession {
	const { id, secret } = record(value);
	if (
		typeof id !== "string" ||
		!/^[a-f\d-]{36}$/i.test(id) ||
		typeof secret !== "string" ||
		!/^[a-f\d]{64}$/.test(secret)
	)
		throw new Error("Sesión de terminal inválida.");
	return { id, secret };
}

export function terminalReadInput(value: unknown) {
	const { offset } = record(value);
	if (!Number.isSafeInteger(offset) || Number(offset) < 0)
		throw new Error("Posición de terminal inválida.");
	return { ...terminalSessionInput(value), offset: Number(offset) };
}

export function terminalWriteInput(value: unknown) {
	const { input } = record(value);
	if (typeof input !== "string" || !input.length || input.length > 8192)
		throw new Error("Entrada de terminal inválida (máximo 8192 caracteres).");
	return { ...terminalSessionInput(value), input };
}

export function terminalResizeInput(value: unknown) {
	return { ...terminalSessionInput(value), ...terminalSize(value) };
}
