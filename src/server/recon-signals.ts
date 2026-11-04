import {
	parseDnsResult,
	parsePtrResult,
	parseTlsResult,
	type ReconQuery,
	type ReconResult,
	reconQueryIssues,
	reconQueryUrl,
	validateReconQuery,
} from "../lib/recon.ts";
import {
	addressRange,
	pinResolvedScope,
	type ScopePlan,
	validateScopePlan,
} from "../lib/scope.ts";

export type SignalProbe = (payload: object) => Promise<unknown>;
export async function collectReconSignals(
	input: ReconQuery,
	planValue: ScopePlan,
	probe: SignalProbe,
	now = Date.now,
): Promise<ReconResult> {
	const query = validateReconQuery(input);
	const plan = validateScopePlan(planValue);
	const issues = reconQueryIssues(query, plan, now());
	if (issues.length) throw new Error(issues.join("\n"));
	const deadline = now() + query.timeoutSeconds * 1000;
	const remaining = () => {
		const milliseconds = Math.min(deadline, Date.parse(plan.windowEnd)) - now();
		if (milliseconds <= 0)
			throw new Error(
				"La ventana terminó o se agotó el timeout de reconocimiento.",
			);
		return milliseconds;
	};
	let parsed: Pick<ReconResult, "facts" | "assets" | "warnings">;
	const ip = addressRange(query.domain);
	if (query.source === "dns") {
		parsed = (ip ? parsePtrResult : parseDnsResult)(
			await probe({
				...(ip
					? { operation: "reverse", address: query.domain }
					: { operation: "dns", domain: query.domain }),
				timeoutMs: remaining(),
			}),
			query.domain,
		);
	} else if (query.source === "tls") {
		const names = [
			...new Set([
				...(ip ? [] : [query.domain]),
				...plan.excludes.filter((name) => !addressRange(name)),
			]),
		];
		if (names.length > 64)
			throw new Error(
				"La comprobación TLS admite hasta 64 nombres entre el objetivo y las exclusiones.",
			);
		const resolved = names.length
			? await probe({
					operation: "resolve",
					names,
					...(ip?.kind === "ipv6" ? { family: 6 } : {}),
					timeoutMs: remaining(),
				})
			: {};
		if (!resolved || typeof resolved !== "object" || Array.isArray(resolved))
			throw new Error("Respuesta DNS inválida.");
		remaining();
		const args = pinResolvedScope(
			[
				...(ip?.kind === "ipv6" ? ["-6"] : []),
				"-sT",
				"-Pn",
				"-sV",
				"-p",
				String(query.port),
				"--max-rate",
				"1",
				query.domain,
			],
			plan,
			resolved as Record<string, string[]>,
			query.timeoutSeconds,
			now(),
		);
		const address = ip
			? query.domain
			: (resolved as Record<string, string[]>)[query.domain][0];
		if (!args.includes(address))
			throw new Error("No se pudo fijar el destino TLS autorizado.");
		parsed = parseTlsResult(
			await probe({
				operation: "tls",
				domain: query.domain,
				address,
				port: query.port,
				timeoutMs: remaining(),
			}),
			query.domain,
			address,
		);
	} else throw new Error("Fuente de señales no compatible.");
	remaining();
	return {
		...parsed,
		source: query.source,
		query: query.domain,
		sourceUrl: reconQueryUrl(query),
		retrievedAt: new Date(now()).toISOString(),
		scopeRevision: plan.revision,
	};
}
