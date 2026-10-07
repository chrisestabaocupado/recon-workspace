import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import type { Client } from "ssh2";
import type { SshSettings } from "../lib/kali.ts";
import { quoteArg } from "../lib/nmap-command.ts";

export function execJsonInput(
	connection: Client,
	source: string,
	payload: object,
	signal: AbortSignal,
	maxBytes = 4500000,
): Promise<unknown> {
	signal.throwIfAborted();
	return new Promise((resolve, reject) => {
		let settled = false;
		let channel: import("ssh2").ClientChannel | undefined;
		const disconnected = () =>
			done(new Error("Se perdió SSH durante la operación en Kali."));
		const failed = (error: Error) => done(error);
		const aborted = () => {
			done(new Error("La operación en Kali agotó su tiempo o fue cancelada."));
			channel?.close();
		};
		const done = (error?: Error, value?: unknown) => {
			if (settled) return;
			settled = true;
			signal.removeEventListener("abort", aborted);
			connection.removeListener("close", disconnected);
			connection.removeListener("error", failed);
			if (error) reject(error);
			else resolve(value);
		};
		signal.addEventListener("abort", aborted, { once: true });
		connection.once("close", disconnected);
		connection.once("error", failed);
		connection.exec(
			`exec node --input-type=module -e ${quoteArg(source)}`,
			(error, stream) => {
				if (error) {
					done(error);
					return;
				}
				channel = stream;
				if (settled || signal.aborted) {
					stream.close();
					aborted();
					return;
				}
				const chunks: Buffer[] = [];
				let bytes = 0;
				let failure = "";
				stream.on("data", (chunk: Buffer) => {
					bytes += chunk.length;
					if (bytes > maxBytes) {
						done(
							new Error("La respuesta de Kali excedió el límite permitido."),
						);
						stream.close();
					} else chunks.push(chunk);
				});
				stream.stderr.on("data", (data: Buffer) => {
					failure = (failure + data.toString()).slice(-4096);
				});
				stream.once("error", failed);
				stream.once("close", (code: number | null) => {
					if (code !== 0) {
						done(
							new Error(
								failure || "La operación remota no confirmó su finalización.",
							),
						);
						return;
					}
					try {
						done(undefined, JSON.parse(Buffer.concat(chunks).toString("utf8")));
					} catch {
						done(new Error("Kali devolvió una respuesta de control inválida."));
					}
				});
				stream.end(JSON.stringify(payload));
			},
		);
	});
}
export async function connectSsh(
	settings: SshSettings,
	signal?: AbortSignal,
): Promise<Client> {
	signal?.throwIfAborted();
	const keyPath = settings.privateKeyPath.startsWith("~/")
		? path.join(os.homedir(), settings.privateKeyPath.slice(2))
		: settings.privateKeyPath;
	const privateKey = await readFile(keyPath);
	signal?.throwIfAborted();
	const { Client: SshClient } = await import("ssh2");
	return new Promise((resolve, reject) => {
		const connection = new SshClient();
		let observedFingerprint = "";
		const abort = () => {
			connection.end();
			reject(new Error("Inicio SSH cancelado."));
		};
		signal?.addEventListener("abort", abort, { once: true });
		const cleanup = () => signal?.removeEventListener("abort", abort);
		connection.once("ready", () => {
			cleanup();
			resolve(connection);
		});
		connection.once("error", (error) => {
			cleanup();
			connection.end();
			reject(
				new Error(
					`${error.message}${observedFingerprint ? `. Huella observada: ${observedFingerprint}` : ""}`,
				),
			);
		});
		connection.once("close", () => {
			cleanup();
			reject(new Error("SSH se cerró antes de completar la conexión."));
		});
		connection.connect({
			host: settings.host.replace(/^\[|\]$/g, ""),
			port: settings.port,
			username: settings.username,
			privateKey,
			passphrase: settings.passphrase,
			readyTimeout: 15000,
			keepaliveInterval: 5000,
			keepaliveCountMax: 3,
			hostVerifier: (key: Buffer) => {
				observedFingerprint = `SHA256:${createHash("sha256").update(key).digest("base64").replace(/=+$/, "")}`;
				return observedFingerprint === settings.fingerprint;
			},
		});
	});
}
export function execJsonEvents(
	connection: Client,
	source: string,
	payload: object,
	signal: AbortSignal,
	emit: (event: unknown) => void,
) {
	signal.throwIfAborted();
	return new Promise<void>((resolve, reject) => {
		let settled = false,
			pending = "",
			bytes = 0;
		let channel: import("ssh2").ClientChannel | undefined;
		const decoder = new StringDecoder("utf8");
		const failed = () =>
			done(new Error("No se pudo confirmar la instalación remota."));
		const done = (error?: Error) => {
			if (settled) return;
			settled = true;
			signal.removeEventListener("abort", failed);
			connection.removeListener("close", failed);
			connection.removeListener("error", failed);
			if (error) {
				channel?.close();
				reject(error);
			} else resolve();
		};
		signal.addEventListener("abort", failed, { once: true });
		connection.once("close", failed);
		connection.once("error", failed);
		connection.exec(
			`exec node --input-type=module -e ${quoteArg(source)}`,
			(error, stream) => {
				if (error) {
					failed();
					return;
				}
				channel = stream;
				if (settled || signal.aborted) {
					stream.close();
					return;
				}
				stream.on("data", (chunk: Buffer) => {
					if (settled) return;
					bytes += chunk.length;
					pending += decoder.write(chunk);
					if (bytes > 8 * 1024 * 1024) {
						failed();
						return;
					}
					for (;;) {
						const end = pending.indexOf("\n");
						if (end < 0) break;
						const line = pending.slice(0, end);
						if (line.length > 65536) {
							failed();
							return;
						}
						pending = pending.slice(end + 1);
						try {
							emit(JSON.parse(line));
						} catch {
							failed();
							return;
						}
					}
					if (pending.length > 65536) failed();
				});
				stream.stderr.resume();
				stream.once("error", failed);
				stream.once("close", (code: number | null) =>
					code === 0 && !pending.trim() ? done() : failed(),
				);
				stream.end(JSON.stringify(payload));
			},
		);
	});
}
export function execText(
	connection: Client,
	command: string,
	signal: AbortSignal,
) {
	signal.throwIfAborted();
	return new Promise<string>((resolve, reject) => {
		let settled = false;
		const aborted = () =>
			done(new Error("Se agotó el tiempo del diagnóstico remoto."));
		const closed = () =>
			done(new Error("SSH se cerró durante el diagnóstico remoto."));
		const done = (error?: Error, value = "") => {
			if (settled) return;
			settled = true;
			signal.removeEventListener("abort", aborted);
			connection.removeListener("close", closed);
			if (error) reject(error);
			else resolve(value);
		};
		signal.addEventListener("abort", aborted, { once: true });
		connection.once("close", closed);
		connection.exec(command, (error, stream) => {
			if (error) {
				done(error);
				return;
			}
			if (settled || signal.aborted) {
				stream.close();
				aborted();
				return;
			}
			let output = "";
			stream.on("data", (data: Buffer) => {
				output = (output + data.toString()).slice(-16384);
			});
			stream.stderr.on("data", (data: Buffer) => {
				output = (output + data.toString()).slice(-16384);
			});
			stream.once("error", (error: Error) => done(error));
			stream.once("close", (code: number | null) =>
				code === 0
					? done(undefined, output)
					: done(new Error(output || "Falló el diagnóstico remoto.")),
			);
		});
	});
}
