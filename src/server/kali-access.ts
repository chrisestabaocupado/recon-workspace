import { createHash, randomUUID } from "node:crypto";
import {
	executorIdentity,
	requireSshExecution,
	type SshSettings,
	sshSettingsSignature,
} from "../lib/kali.ts";

const TTL = 15 * 60 * 1000;
export class KaliVerificationStore {
	private entries = new Map<string, { digest: string; expiresAt: number }>();
	issue(settings: SshSettings, now = Date.now()) {
		for (const [token, entry] of this.entries)
			if (entry.expiresAt <= now) this.entries.delete(token);
		if (this.entries.size >= 64)
			this.entries.delete(this.entries.keys().next().value as string);
		const token = randomUUID();
		const expiresAt = now + TTL;
		this.entries.set(token, { digest: this.digest(settings), expiresAt });
		return {
			token,
			expiresAt: new Date(expiresAt).toISOString(),
			executor: executorIdentity(settings),
		};
	}
	require(value: unknown, now = Date.now()) {
		const access = requireSshExecution(value);
		const entry = this.entries.get(access.kaliToken);
		if (
			!entry ||
			entry.expiresAt <= now ||
			entry.digest !== this.digest(access.ssh)
		)
			throw new Error(
				"La verificación de Kali caducó, cambió o se perdió al reiniciar el servidor. Comprueba SSH de nuevo.",
			);
		return access;
	}
	private digest(settings: SshSettings) {
		return createHash("sha256")
			.update(sshSettingsSignature(settings))
			.digest("hex");
	}
}
export const kaliVerifications = new KaliVerificationStore();
