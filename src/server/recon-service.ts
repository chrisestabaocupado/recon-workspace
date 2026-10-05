import {
	parseCrtResult,
	parseRdapResult,
	type ReconQuery,
	type ReconResult,
	reconQueryIssues,
	reconQueryUrl,
	validateReconQuery,
} from "../lib/recon.ts";
import {
	normalizeScopeEntry,
	type ScopePlan,
	validateScopePlan,
} from "../lib/scope.ts";

export const RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
const MAX_RESPONSE_BYTES = 3 * 1024 * 1024;
export type ReconFetch = (url: string, init: RequestInit) => Promise<Response>;

export async function readReconJson(
	response: Response,
	limit = MAX_RESPONSE_BYTES,
	source?: "crtsh" | "rdap",
): Promise<unknown> {
	if (!response.ok) {
		await response.body?.cancel();
		if (response.status === 429)
			throw new Error(
				"La fuente limitó las consultas (429). Espera antes de volver a consultar.",
			);
		if (response.status === 404)
			throw new Error(
				source === "rdap"
					? "El servicio RDAP devolvió HTTP 404 para el dominio consultado. RDAP requiere el dominio registrable exacto; no se amplía automáticamente la consulta."
					: source === "crtsh"
						? "crt.sh devolvió HTTP 404 para la consulta. Esto no confirma que no existan certificados para el dominio. Reintenta más tarde o usa una fuente manual."
						: "La fuente devolvió HTTP 404 para el recurso solicitado; no se pudo obtener su información.",
			);
		throw new Error(
			`La fuente no respondió correctamente (HTTP ${response.status}).`,
		);
	}
	if (!response.body)
		throw new Error("La fuente devolvió una respuesta vacía.");
	if (Number(response.headers.get("content-length")) > limit) {
		await response.body.cancel();
		throw new Error(
			"La respuesta supera 3 MB. Reduce la consulta o importa evidencia manual.",
		);
	}
	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	let count = 0;
	let output = "";
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			count += value.byteLength;
			if (count > limit) {
				await reader.cancel();
				throw new Error(
					"La respuesta supera 3 MB. Reduce la consulta o importa evidencia manual.",
				);
			}
			output += decoder.decode(value, { stream: true });
		}
		output += decoder.decode();
	} finally {
		reader.releaseLock();
	}
	try {
		return JSON.parse(output);
	} catch {
		throw new Error(
			"La fuente no devolvió JSON válido; puede estar temporalmente indisponible.",
		);
	}
}

// Only endpoint origins published by IANA can be contacted. Redirects are rejected;
// neither a client-supplied URL nor a location in the registry response is fetched.
export function rdapDomainUrl(bootstrap: unknown, domain: string): string {
	if (
		!bootstrap ||
		typeof bootstrap !== "object" ||
		!Array.isArray((bootstrap as { services?: unknown }).services)
	)
		throw new Error("Directorio IANA inválido.");
	const services = (bootstrap as { services: unknown[] }).services;
	const tld = domain.split(".").at(-1);
	for (const service of services) {
		if (
			!Array.isArray(service) ||
			!Array.isArray(service[0]) ||
			!service[0].includes(tld) ||
			!Array.isArray(service[1])
		)
			continue;
		for (const endpoint of service[1]) {
			if (typeof endpoint !== "string") continue;
			let base: URL;
			try {
				base = new URL(endpoint);
			} catch {
				continue;
			}
			if (
				base.protocol !== "https:" ||
				base.username ||
				base.password ||
				base.port ||
				base.search ||
				base.hash ||
				!base.hostname.includes(".") ||
				base.hostname.includes(":")
			)
				continue;
			try {
				normalizeScopeEntry(base.hostname);
			} catch {
				continue;
			}
			if (
				/^[\d.]+$/.test(base.hostname) ||
				/\.(?:localhost|local|test|internal|invalid)$/.test(base.hostname)
			)
				continue;
			const url = new URL(
				`domain/${domain}`,
				base.href.endsWith("/") ? base : `${base.href}/`,
			);
			if (url.origin === base.origin) return url.href;
		}
	}
	throw new Error(
		"IANA no publica un servicio RDAP HTTPS compatible para este dominio. Usa una fuente manual.",
	);
}

export async function collectRecon(
	input: ReconQuery,
	planValue: ScopePlan,
	fetcher: ReconFetch,
	now: () => number = Date.now,
): Promise<ReconResult> {
	const query = validateReconQuery(input);
	if (query.source === "dns" || query.source === "tls")
		throw new Error("Esta fuente requiere el transporte de señales de Kali.");
	const plan = validateScopePlan(planValue);
	const issues = reconQueryIssues(query, plan, now());
	if (issues.length) throw new Error(issues.join("\n"));
	if (typeof fetcher !== "function")
		throw new Error(
			"El reconocimiento exige un transporte remoto de Kali; no hay ejecución local.",
		);
	const controller = new AbortController();
	const timer = setTimeout(
		() => controller.abort(),
		query.timeoutSeconds * 1000,
	);
	const init: RequestInit = {
		signal: controller.signal,
		redirect: "error",
		credentials: "omit",
		headers: {
			Accept: "application/rdap+json, application/json",
			"User-Agent": "one-two-three-recon/1.0",
		},
	};
	const started = now();
	try {
		let sourceUrl = reconQueryUrl(query);
		if (query.source === "rdap") {
			const directory = await readReconJson(
				await fetcher(RDAP_BOOTSTRAP_URL, init),
			);
			sourceUrl = rdapDomainUrl(directory, query.domain);
			if (
				now() - started >= query.timeoutSeconds * 1000 ||
				now() >= Date.parse(plan.windowEnd) ||
				controller.signal.aborted
			)
				throw new Error(
					"La ventana terminó o el timeout se agotó antes de consultar el registro.",
				);
		}
		const payload = await readReconJson(
			await fetcher(sourceUrl, init),
			MAX_RESPONSE_BYTES,
			query.source,
		);
		if (
			controller.signal.aborted ||
			now() - started >= query.timeoutSeconds * 1000 ||
			now() > Date.parse(plan.windowEnd)
		)
			throw new Error(
				"La consulta terminó fuera de la ventana o superó el timeout.",
			);
		const parsed =
			query.source === "crtsh"
				? parseCrtResult(payload, query)
				: parseRdapResult(payload, query.domain);
		return {
			...parsed,
			source: query.source,
			query: query.domain,
			sourceUrl,
			retrievedAt: new Date(now()).toISOString(),
			scopeRevision: plan.revision,
		};
	} catch (error) {
		if (controller.signal.aborted)
			throw new Error(
				`La consulta agotó su timeout de ${query.timeoutSeconds} segundos.`,
			);
		if (error instanceof TypeError)
			throw new Error(
				"No se pudo consultar la fuente por conexión, TLS o una redirección no permitida. Puedes importar su JSON manualmente.",
			);
		throw error;
	} finally {
		clearTimeout(timer);
	}
}
