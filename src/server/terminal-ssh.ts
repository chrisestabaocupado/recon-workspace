import { StringDecoder } from "node:string_decoder";
import type { Client, ClientChannel } from "ssh2";
import type { TerminalSize } from "../lib/terminal.ts";
import type { TerminalTransport } from "./terminal-manager.ts";

// A real PTY on the verified remote host, never a local process or exec string.
export function openSshTerminal(
	connection: Client,
	size: TerminalSize,
	signal: AbortSignal,
	output: (data: string) => void,
	closed: (message: string) => void,
): Promise<TerminalTransport> {
	return new Promise((resolve, reject) => {
		let channel: ClientChannel | undefined;
		let stopped = false;
		const stdout = new StringDecoder("utf8");
		const stderr = new StringDecoder("utf8");
		const stop = (message = "Se perdió la conexión SSH con la terminal.") => {
			if (stopped) return;
			stopped = true;
			clearTimeout(timer);
			signal.removeEventListener("abort", abort);
			channel?.close();
			connection.end();
			closed(message);
			reject(new Error(message));
		};
		const abort = () => stop("Sesión de terminal cerrada.");
		const timer = setTimeout(
			() => stop("Kali no abrió la terminal a tiempo."),
			15000,
		);
		timer.unref();
		connection.once("close", () => stop());
		connection.on("error", () => stop());
		signal.addEventListener("abort", abort, { once: true });
		if (signal.aborted) {
			abort();
			return;
		}
		connection.shell(
			{ term: "xterm-256color", cols: size.cols, rows: size.rows },
			(error, stream) => {
				if (error) {
					stop("No se pudo abrir un shell interactivo en Kali.");
					return;
				}
				if (stopped) {
					stream.on("error", () => {});
					stream.close();
					return;
				}
				channel = stream;
				clearTimeout(timer);
				stream.on("data", (data: Buffer) => output(stdout.write(data)));
				stream.stderr.on("data", (data: Buffer) => output(stderr.write(data)));
				stream.on("error", () => stop());
				stream.stderr.on("error", () => stop());
				stream.once("close", () => {
					output(stdout.end() + stderr.end());
					stop("El shell remoto se cerró.");
				});
				resolve({
					write: (input) => {
						if (stopped || stream.destroyed)
							throw new Error("La terminal ya está desconectada.");
						if (stream.writableLength > 65536)
							throw new Error(
								"Kali no está procesando la entrada de la terminal.",
							);
						stream.write(input);
					},
					resize: ({ cols, rows }) => {
						if (!stopped) stream.setWindow(rows, cols, 0, 0);
					},
					close: abort,
				});
			},
		);
	});
}
