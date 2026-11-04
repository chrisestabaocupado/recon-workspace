import { createServerFn } from "@tanstack/react-start";
import { connectSsh } from "./ssh.ts";
import {
	terminalReadInput,
	terminalResizeInput,
	terminalSessionInput,
	terminalStartInput,
	terminalWriteInput,
} from "./terminal-input.ts";
import { TerminalManager } from "./terminal-manager.ts";
import { openSshTerminal } from "./terminal-ssh.ts";

const terminals = new TerminalManager();

export const startTerminal = createServerFn({ method: "POST" })
	.validator((value: unknown) => terminalStartInput(value))
	.handler(async ({ data }) =>
		terminals.start(async (signal, output, closed) => {
			const connection = await connectSsh(data.ssh, signal);
			try {
				return await openSshTerminal(connection, data, signal, output, closed);
			} catch (error) {
				connection.end();
				throw error;
			}
		}),
	);

// Capabilities stay in memory and are sent only in POST bodies, never URLs.
export const readTerminal = createServerFn({ method: "POST" })
	.validator(terminalReadInput)
	.handler(({ data }) => terminals.read(data, data.offset));

export const writeTerminal = createServerFn({ method: "POST" })
	.validator(terminalWriteInput)
	.handler(({ data }) => {
		terminals.write(data, data.input);
		return { ok: true };
	});

export const resizeTerminal = createServerFn({ method: "POST" })
	.validator(terminalResizeInput)
	.handler(({ data }) => {
		terminals.resize(data, data);
		return { ok: true };
	});

export const closeTerminal = createServerFn({ method: "POST" })
	.validator(terminalSessionInput)
	.handler(({ data }) => {
		terminals.close(data);
		return { ok: true };
	});
