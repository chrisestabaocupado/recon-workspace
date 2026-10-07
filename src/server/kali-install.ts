import { createHash } from "node:crypto";
import { createServerFn } from "@tanstack/react-start";
import type { Client } from "ssh2";
import {
	type KaliAccess,
	requireSshExecution,
	sshSettingsSignature,
} from "../lib/kali.ts";
import { validateKaliInstallInput } from "./kali-install-input.ts";
import { KaliInstallManager } from "./kali-install-manager.ts";
import source from "./remote-install.mjs?raw";
import { connectSsh, execJsonEvents } from "./ssh.ts";

const manager = new KaliInstallManager();
function owner(access: KaliAccess) {
	return createHash("sha256")
		.update(sshSettingsSignature(access.ssh))
		.update(access.kaliToken)
		.digest("hex");
}
export const startKaliInstallation = createServerFn({ method: "POST" })
	.validator((value: unknown) => validateKaliInstallInput(value))
	.handler(({ data }) =>
		manager.start(owner(data.access), data.tools, async (emit) => {
			const signal = AbortSignal.timeout(15 * 60 * 1000);
			let connection: Client | undefined;
			const abort = () => connection?.end();
			signal.addEventListener("abort", abort, { once: true });
			try {
				connection = await connectSsh(data.access.ssh, signal);
				await execJsonEvents(
					connection,
					source,
					{ tools: data.tools, sudoPassword: data.sudoPassword },
					signal,
					emit,
				);
			} catch (error) {
				if (!connection)
					emit({
						type: "done",
						code: 1,
						error:
							"No se pudo conectar por SSH a Kali. No se inició APT; comprueba la conexión antes de reintentar.",
					});
				else throw error;
			} finally {
				data.sudoPassword = "";
				signal.removeEventListener("abort", abort);
				connection?.end();
			}
		}),
	);
export const getKaliInstallation = createServerFn({ method: "POST" })
	.validator((value: unknown) => {
		const access = requireSshExecution(value);
		const id = (value as { id?: unknown }).id;
		if (typeof id !== "string" || !/^[a-f\d-]{36}$/i.test(id))
			throw new Error("Instalación inválida.");
		return { access, id };
	})
	.handler(({ data }) => manager.get(data.id, owner(data.access)));
