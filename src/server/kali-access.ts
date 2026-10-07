import { createHash, randomUUID } from "node:crypto";
import {
	executorIdentity,
	type KaliToolCheck,
	kaliToolIssue,
	requireSshExecution,
	type SshSettings,
	sshSettingsSignature,
} from "../lib/kali.ts";

const TTL = 15 * 60 * 1000;
export class KaliVerificationStore {
	private entries = new Map<
		string,
		{ digest: string; expiresAt: number; tools: KaliToolCheck[] }
	>();
	issue(settings: SshSettings, now = Date.now(), tools: KaliToolCheck[] = []) {
		for (const [token, entry] of this.entries)
			if (entry.expiresAt <= now) this.entries.delete(token);
		if (this.entries.size >= 64)
			this.entries.delete(this.entries.keys().next().value as string);
		const token = randomUUID();
		const expiresAt = now + TTL;
		this.entries.set(token, {
			digest: this.digest(settings),
			expiresAt,
			tools: structuredClone(tools),
		});
		return {
			token,
			expiresAt: new Date(expiresAt).toISOString(),
			executor: executorIdentity(settings),
			tools: structuredClone(tools),
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
	requireTool(value: unknown, tool: string, now = Date.now()) {
		const access = this.require(value, now);
		const issue = kaliToolIssue(
			this.entries.get(access.kaliToken)?.tools,
			tool,
		);
		if (issue) throw new Error(issue);
		return access;
	}
	private digest(settings: SshSettings) {
		return createHash("sha256")
			.update(sshSettingsSignature(settings))
			.digest("hex");
	}
	tools(value: unknown, now = Date.now()) {
		const access = this.require(value, now);
		return structuredClone(this.entries.get(access.kaliToken)?.tools ?? []);
	}
}
export const kaliVerifications = new KaliVerificationStore();
