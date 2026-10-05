import type { Client } from "ssh2";
import { executorIdentity, type KaliAccess } from "../lib/kali.ts";
import type { ReconQuery } from "../lib/recon.ts";
import type { ScopePlan } from "../lib/scope.ts";
import { collectRecon, type ReconFetch } from "./recon-service.ts";
import { collectReconSignals } from "./recon-signals.ts";
import remoteHttpSource from "./remote-http.mjs?raw";
import { remoteHttpResponse } from "./remote-http-protocol.ts";
import remoteSignalsSource from "./remote-signals.mjs?raw";
import { connectSsh, execJsonInput } from "./ssh.ts";

export async function collectRemoteRecon(
	query: ReconQuery,
	plan: ScopePlan,
	access: KaliAccess,
) {
	let connection: Client | undefined;
	const deadline = Date.now() + query.timeoutSeconds * 1000;
	const signal = AbortSignal.timeout(query.timeoutSeconds * 1000);
	const abort = () => connection?.end();
	signal.addEventListener("abort", abort, { once: true });
	const fetcher: ReconFetch = async (url) => {
		signal.throwIfAborted();
		connection ??= await connectSsh(access.ssh, signal);
		const remaining = deadline - Date.now();
		if (remaining <= 0)
			throw new Error(
				"Se agotó el tiempo de reconocimiento antes de consultar la fuente en Kali.",
			);
		return remoteHttpResponse(
			await execJsonInput(
				connection,
				remoteHttpSource,
				{ url, timeoutMs: Math.min(60000, remaining) },
				signal,
			),
		);
	};
	try {
		if (query.source === "dns" || query.source === "tls") {
			const result = await collectReconSignals(query, plan, async (payload) => {
				signal.throwIfAborted();
				connection ??= await connectSsh(access.ssh, signal);
				const remaining = deadline - Date.now();
				if (remaining <= 0)
					throw new Error("Se agotó el timeout antes de consultar Kali.");
				return execJsonInput(
					connection,
					remoteSignalsSource,
					{ ...payload, timeoutMs: remaining },
					signal,
				);
			});
			return { ...result, executor: executorIdentity(access.ssh) };
		}
		return {
			...(await collectRecon(query, plan, fetcher)),
			executor: executorIdentity(access.ssh),
		};
	} finally {
		signal.removeEventListener("abort", abort);
		connection?.end();
	}
}
