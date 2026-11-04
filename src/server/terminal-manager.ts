import { randomBytes, randomUUID } from "node:crypto";
import type {
	TerminalFrame,
	TerminalSession,
	TerminalSize,
} from "../lib/terminal.ts";

export type TerminalTransport = {
	write: (input: string) => void;
	resize: (size: TerminalSize) => void;
	close: () => void;
};
export type TerminalLaunch = (
	signal: AbortSignal,
	output: (data: string) => void,
	closed: (message: string) => void,
) => Promise<TerminalTransport>;
type Entry = {
	secret: string;
	controller: AbortController;
	transport?: TerminalTransport;
	timer?: ReturnType<typeof setTimeout>;
	data: string;
	base: number;
	state: TerminalFrame["state"];
	message: string;
};
const OUTPUT_LIMIT = 256 * 1024;

export class TerminalManager {
	private entries = new Map<string, Entry>();
	private idleMs: number;
	constructor(idleMs = 60000) {
		this.idleMs = idleMs;
	}

	async start(launch: TerminalLaunch): Promise<TerminalSession> {
		if (this.entries.size >= 4)
			throw new Error(
				"Hay demasiadas terminales abiertas. Cierra una y reintenta.",
			);
		const id = randomUUID();
		const entry: Entry = {
			secret: randomBytes(32).toString("hex"),
			controller: new AbortController(),
			data: "",
			base: 0,
			state: "connected",
			message: "",
		};
		this.entries.set(id, entry);
		this.touch(id, entry);
		try {
			const transport = await launch(
				entry.controller.signal,
				(data) => {
					if (entry.state === "closed") return;
					entry.data += data;
					if (entry.data.length > OUTPUT_LIMIT) {
						let removed = entry.data.length - OUTPUT_LIMIT;
						// Never start the retained window in the middle of a UTF-16 pair.
						const code = entry.data.charCodeAt(removed);
						if (code >= 0xdc00 && code <= 0xdfff) removed++;
						entry.base += removed;
						entry.data = entry.data.slice(removed);
					}
				},
				(message) => this.finish(entry, message),
			);
			entry.transport = transport;
			if (entry.state === "closed" || entry.controller.signal.aborted)
				transport.close();
			entry.controller.signal.throwIfAborted();
			return { id, secret: entry.secret };
		} catch (error) {
			this.remove(id, entry);
			throw error;
		}
	}

	read(session: TerminalSession, offset: number): TerminalFrame {
		const entry = this.require(session);
		if (offset > entry.base + entry.data.length)
			throw new Error("Posición de terminal fuera de rango.");
		return {
			data: entry.data.slice(Math.max(0, offset - entry.base)),
			offset: entry.base + entry.data.length,
			truncated: offset < entry.base,
			state: entry.state,
			message: entry.message,
		};
	}
	write(session: TerminalSession, input: string) {
		const entry = this.require(session);
		if (entry.state !== "connected" || !entry.transport)
			throw new Error("La terminal ya está desconectada.");
		entry.transport.write(input);
	}
	resize(session: TerminalSession, size: TerminalSize) {
		const entry = this.require(session);
		if (entry.state === "connected") entry.transport?.resize(size);
	}
	close(session: TerminalSession) {
		this.remove(session.id, this.require(session));
	}
	private require(session: TerminalSession) {
		const entry = this.entries.get(session.id);
		if (!entry || entry.secret !== session.secret)
			throw new Error(
				"La sesión de terminal no existe o caducó. Abre una nueva.",
			);
		this.touch(session.id, entry);
		return entry;
	}
	private touch(id: string, entry: Entry) {
		clearTimeout(entry.timer);
		entry.timer = setTimeout(() => this.remove(id, entry), this.idleMs);
		entry.timer.unref();
	}
	private finish(entry: Entry, message: string) {
		if (entry.state === "closed") return;
		entry.state = "closed";
		entry.message = message;
		entry.controller.abort();
		entry.transport?.close();
	}
	private remove(id: string, entry: Entry) {
		clearTimeout(entry.timer);
		this.entries.delete(id);
		this.finish(entry, "Sesión de terminal cerrada.");
		entry.data = "";
	}
}
