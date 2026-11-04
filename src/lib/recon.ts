import { type KaliExecutor, validateExecutor } from "./kali.ts";
import { quoteArg, tokenizeCommand } from "./nmap-command.ts";
import { redactText } from "./redaction.ts";
import {
	addressRange,
	approvalIssues,
	normalizeScopeEntry,
	portRanges,
	type ScopePlan,
	targetDecision,
} from "./scope.ts";

export const reconSources = {
	crtsh: "Certificados · crt.sh",
	rdap: "Registro · RDAP",
	dns: "DNS · registros / inverso (PTR)",
	tls: "TLS · certificado del servicio",
	manual: "Evidencia manual",
} as const;
export type ReconSource = keyof typeof reconSources;
export type ReconQuery = {
	source: "crtsh" | "rdap" | "dns" | "tls";
	domain: string;
	subdomains: boolean;
	timeoutSeconds: number;
	port?: number;
};
export type ReconResult = {
	source: ReconSource;
	query: string;
	sourceUrl: string;
	retrievedAt: string;
	scopeRevision?: number;
	executor?: KaliExecutor;
	facts: { label: string; value: string }[];
	warnings: string[];
	issues?: { stage: string; error: string }[];
	assets: string[];
};
export type ReconEvidence = Omit<ReconResult, "assets"> & {
	id: string;
	notes: string;
};
export type ReconAsset = {
	id: string;
	value: string;
	evidenceIds: string[];
	status: "candidate" | "reviewed" | "discarded";
	note: string;
	updatedAt: string;
};
export type ReconData = {
	version: 1;
	evidence: ReconEvidence[];
	assets: ReconAsset[];
};
export const emptyRecon = (): ReconData => ({
	version: 1,
	evidence: [],
	assets: [],
});
export const defaultReconQuery = (): ReconQuery => ({
	source: "dns",
	domain: "",
	subdomains: false,
	timeoutSeconds: 25,
});
export const MAX_RECON_ASSETS = 2500;
export const MAX_QUERY_ASSETS = 500;

export function publicDomain(value: string): string {
	const domain = normalizeScopeEntry(value);
	if (
		addressRange(domain) ||
		!domain.includes(".") ||
		/\.(?:local|localhost|internal|test|invalid|example|onion|arpa)$/.test(
			domain,
		) ||
		/^(?:example\.(?:com|net|org)|localhost)$/.test(domain)
	)
		throw new Error(
			"Esta fuente requiere un dominio público exacto. Para una IP individual selecciona DNS inverso o TLS; para redes o nombres internos usa evidencia manual.",
		);
	return domain;
}
export function reconTarget(value: string): string {
	const target = normalizeScopeEntry(value);
	if (target.includes("/"))
		throw new Error(
			"Indica un dominio público o una IP individual, no una red CIDR.",
		);
	return addressRange(target) ? target : publicDomain(target);
}
export function validateReconQuery(value: unknown): ReconQuery {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error("Consulta inválida.");
	const query = value as ReconQuery;
	if (!["crtsh", "rdap", "dns", "tls"].includes(query.source))
		throw new Error("Fuente no compatible.");
	if (typeof query.domain !== "string") throw new Error("Dominio inválido.");
	if (typeof query.subdomains !== "boolean")
		throw new Error("Filtro de subdominios inválido.");
	if (query.source !== "crtsh" && query.subdomains)
		throw new Error(
			"Esta fuente requiere un dominio exacto; desactiva subdominios.",
		);
	if (
		query.source === "tls" &&
		(!Number.isInteger(query.port ?? 443) ||
			(query.port ?? 443) < 1 ||
			(query.port ?? 443) > 65535)
	)
		throw new Error("Puerto TLS inválido.");
	if (
		!Number.isInteger(query.timeoutSeconds) ||
		query.timeoutSeconds < 5 ||
		query.timeoutSeconds > 60
	)
		throw new Error("El timeout debe estar entre 5 y 60 segundos.");
	return {
		source: query.source,
		domain:
			query.source === "dns" || query.source === "tls"
				? reconTarget(query.domain)
				: publicDomain(query.domain),
		subdomains: query.subdomains,
		timeoutSeconds: query.timeoutSeconds,
		...(query.source === "tls" ? { port: query.port ?? 443 } : {}),
	};
}
export function reconQueryIssues(
	query: ReconQuery,
	plan?: ScopePlan,
	now = Date.now(),
): string[] {
	let validated: ReconQuery;
	try {
		validated = validateReconQuery(query);
	} catch (error) {
		return [error instanceof Error ? error.message : "Consulta inválida."];
	}
	if (!plan || plan.status !== "approved")
		return [
			"Completa y aprueba el plan de alcance antes de ejecutar reconocimiento.",
		];
	const issues = approvalIssues(plan, now);
	if (validated.source === "tls") {
		if (!plan.techniques.tcp || !plan.techniques.services)
			issues.push(
				"La lectura TLS conecta al servicio y requiere enumeración TCP e identificación de servicios en el plan.",
			);
		if (
			!portRanges(plan.allowedPorts).some(
				([first, last]) =>
					(validated.port ?? 443) >= first && (validated.port ?? 443) <= last,
			)
		)
			issues.push("El puerto TLS no está permitido en el plan.");
	} else if (!plan.passiveRecon)
		issues.push(
			"Habilita Reconocimiento pasivo (fuentes públicas y consultas DNS) en las reglas del plan y registra su nueva aprobación.",
		);
	if (now < Date.parse(plan.windowStart))
		issues.push("La ventana de pruebas todavía no ha comenzado.");
	if (now + validated.timeoutSeconds * 1000 > Date.parse(plan.windowEnd))
		issues.push("La consulta no cabe en la ventana acordada.");
	if (validated.timeoutSeconds > plan.maxDurationSeconds)
		issues.push("El timeout supera el límite del plan.");
	const decision = targetDecision(validated.domain, plan);
	if (!decision.allowed) issues.push(decision.reason);
	return [...new Set(issues)];
}
export function reconQueryUrl(query: ReconQuery): string {
	const q = validateReconQuery(query);
	if (q.source === "dns") return "";
	if (q.source === "tls")
		return `https://${q.domain.includes(":") ? `[${q.domain}]` : q.domain}:${q.port}/`;
	if (q.source === "rdap") return `https://rdap.org/domain/${q.domain}`;
	const url = new URL("https://crt.sh/");
	url.searchParams.set("q", q.subdomains ? `%.${q.domain}` : q.domain);
	url.searchParams.set("output", "json");
	return url.href;
}
export function buildReconCommand(query: ReconQuery): string {
	const q = validateReconQuery(query);
	const ip = addressRange(q.domain);
	if (q.source === "dns" && ip)
		return `dig +time=${q.timeoutSeconds} +tries=1 -x ${quoteArg(q.domain)} +noall +answer`;
	if (q.source === "dns")
		return ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
			.map(
				(type) =>
					`dig +time=${q.timeoutSeconds} +tries=1 ${quoteArg(q.domain)} ${type} +noall +answer`,
			)
			.join("\n");
	if (q.source === "tls")
		return `timeout ${q.timeoutSeconds}s openssl s_client -connect ${quoteArg(`${ip?.kind === "ipv6" ? `[${q.domain}]` : q.domain}:${q.port}`)} ${ip ? "-noservername" : `-servername ${quoteArg(q.domain)}`} -showcerts </dev/null`;
	return [
		"curl",
		"--fail",
		"--silent",
		"--show-error",
		...(q.source === "rdap" ? ["--location"] : []),
		"--max-time",
		String(q.timeoutSeconds),
		reconQueryUrl(q),
	]
		.map(quoteArg)
		.join(" ");
}
export function parseReconCommand(command: string): ReconQuery {
	let args: string[];
	try {
		args = tokenizeCommand(command);
	} catch {
		throw new Error(
			"Comando incompleto o con operadores de shell. Pon la URL entre comillas simples.",
		);
	}
	if (!["curl", "curl.exe"].includes(args.shift() ?? ""))
		throw new Error("Usa curl y una URL de crt.sh o rdap.org.");
	let timeout: number | undefined;
	let url: URL | undefined;
	let location = false;
	const flags = new Set<string>();
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (
			[
				"--fail",
				"--silent",
				"--show-error",
				"--location",
				"-f",
				"-s",
				"-S",
				"-L",
				"-fsS",
				"-fsSL",
			].includes(arg)
		) {
			if (flags.has(arg)) throw new Error("No repitas opciones.");
			flags.add(arg);
			if (arg === "--location" || arg === "-L" || arg === "-fsSL")
				location = true;
		} else if (arg === "--max-time" || arg === "-m") {
			if (timeout !== undefined) throw new Error("Indica un único timeout.");
			const seconds = args[++i];
			if (!/^\d+$/.test(seconds ?? "")) throw new Error("Timeout inválido.");
			timeout = Number(seconds);
		} else {
			if (url || arg.startsWith("-"))
				throw new Error(
					`Opción no soportada: ${arg}. No se descartará silenciosamente.`,
				);
			try {
				url = new URL(arg);
			} catch {
				throw new Error("URL inválida.");
			}
		}
	}
	if (
		!url ||
		url.protocol !== "https:" ||
		url.username ||
		url.password ||
		url.port ||
		url.hash
	)
		throw new Error(
			"Usa una URL HTTPS de fuente pública sin credenciales, puertos ni fragmentos.",
		);
	let query: ReconQuery;
	if (
		url.hostname === "crt.sh" &&
		url.pathname === "/" &&
		!location &&
		url.searchParams.get("output") === "json" &&
		[...url.searchParams.keys()].sort().join(",") === "output,q"
	) {
		const name = url.searchParams.get("q") ?? "";
		query = {
			source: "crtsh",
			domain: name.startsWith("%.") ? name.slice(2) : name,
			subdomains: name.startsWith("%."),
			timeoutSeconds: timeout ?? 25,
		};
	} else if (
		url.hostname === "rdap.org" &&
		/^\/domain\/[^/]+$/.test(url.pathname) &&
		!url.search &&
		location
	) {
		query = {
			source: "rdap",
			domain: decodeURIComponent(url.pathname.slice(8)),
			subdomains: false,
			timeoutSeconds: timeout ?? 25,
		};
	} else
		throw new Error(
			"URL u opciones fuera del adaptador. RDAP necesita --location; crt.sh acepta q y output=json.",
		);
	return validateReconQuery(query);
}

function object(value: unknown, label: string): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error(`${label}: estructura inválida.`);
	return value as Record<string, unknown>;
}
function text(
	value: unknown,
	label: string,
	max = 8192,
	empty = false,
): string {
	if (
		typeof value !== "string" ||
		value.length > max ||
		(!empty && !value.trim())
	)
		throw new Error(`${label}: texto inválido.`);
	return redactText(value);
}
function date(value: unknown): string {
	const parsed = text(value, "Fecha", 100);
	if (!Number.isFinite(Date.parse(parsed)))
		throw new Error("Fecha de evidencia inválida.");
	return new Date(parsed).toISOString();
}
function list(value: unknown, max: number, label: string): unknown[] {
	if (!Array.isArray(value) || value.length > max)
		throw new Error(`${label}: lista inválida o demasiado extensa.`);
	return value;
}
function safeSourceUrl(value: unknown): string {
	const input = text(value, "Fuente", 2048, true);
	if (!input) return "";
	const url = new URL(input);
	if (!/^https?:$/.test(url.protocol) || url.username || url.password)
		throw new Error("La fuente debe ser una URL HTTP(S) sin credenciales.");
	return url.href;
}
function validateEvidence(value: unknown): ReconEvidence {
	const e = object(value, "Evidencia");
	if (!Object.hasOwn(reconSources, String(e.source)))
		throw new Error("Fuente de evidencia inválida.");
	if (
		e.scopeRevision !== undefined &&
		(!Number.isSafeInteger(e.scopeRevision) || Number(e.scopeRevision) < 1)
	)
		throw new Error("Revisión de alcance inválida.");
	return {
		id: text(e.id, "ID", 128),
		source: e.source as ReconSource,
		query: text(e.query, "Consulta", 1024),
		sourceUrl: safeSourceUrl(e.sourceUrl),
		retrievedAt: date(e.retrievedAt),
		scopeRevision: e.scopeRevision as number | undefined,
		executor:
			e.executor === undefined ? undefined : validateExecutor(e.executor),
		facts: list(e.facts, 100, "Datos").map((f) => {
			const field = object(f, "Dato");
			return {
				label: text(field.label, "Campo", 200),
				value: text(field.value, "Dato", 8192, true),
			};
		}),
		warnings: list(e.warnings, 20, "Avisos").map((w) => text(w, "Aviso", 2048)),
		notes: text(e.notes, "Notas", 8192, true),
	};
}
export function validateReconData(value: unknown): ReconData {
	const data = object(value, "Reconocimiento");
	if (data.version !== 1)
		throw new Error("Versión de reconocimiento incompatible.");
	const evidence = list(data.evidence, 100, "Evidencias").map(validateEvidence);
	const ids = new Set(evidence.map((e) => e.id));
	if (ids.size !== evidence.length)
		throw new Error("IDs de evidencia duplicados.");
	const assets = list(data.assets, MAX_RECON_ASSETS, "Activos candidatos").map(
		(value): ReconAsset => {
			const asset = object(value, "Activo");
			if (
				!["candidate", "reviewed", "discarded"].includes(String(asset.status))
			)
				throw new Error("Estado de activo inválido.");
			const evidenceIds = list(asset.evidenceIds, 100, "Fuentes").map((id) =>
				text(id, "ID de evidencia", 128),
			);
			if (
				!evidenceIds.length ||
				evidenceIds.some((id) => !ids.has(id)) ||
				new Set(evidenceIds).size !== evidenceIds.length
			)
				throw new Error("Referencias de evidencia inválidas.");
			return {
				id: text(asset.id, "ID de activo", 128),
				value: normalizeScopeEntry(text(asset.value, "Activo", 256)),
				evidenceIds,
				status: asset.status as ReconAsset["status"],
				note: text(asset.note, "Nota", 4096, true),
				updatedAt: date(asset.updatedAt),
			};
		},
	);
	if (
		new Set(assets.map((a) => a.id)).size !== assets.length ||
		new Set(assets.map((a) => a.value)).size !== assets.length
	)
		throw new Error("Activos duplicados.");
	return { version: 1, evidence, assets };
}
export function mergeReconResult(
	current: ReconData | undefined,
	result: ReconResult,
	notes = "",
	newId: () => string = () => crypto.randomUUID(),
): ReconData {
	const data = current ? validateReconData(current) : emptyRecon();
	if (data.evidence.length >= 100)
		throw new Error(
			"Límite de 100 evidencias. Exporta y elimina evidencias antiguas antes de añadir más.",
		);
	const e = validateEvidence({ ...result, id: newId(), notes });
	const assets = structuredClone(data.assets);
	for (const value of [...new Set(result.assets.map(normalizeScopeEntry))]) {
		const existing = assets.find((a) => a.value === value);
		if (existing) {
			existing.evidenceIds.push(e.id);
		} else {
			assets.push({
				id: newId(),
				value,
				evidenceIds: [e.id],
				status: "candidate",
				note: "",
				updatedAt: e.retrievedAt,
			});
		}
	}
	return validateReconData({
		version: 1,
		evidence: [e, ...data.evidence],
		assets,
	});
}
export function removeReconEvidence(data: ReconData, id: string): ReconData {
	return validateReconData({
		...data,
		evidence: data.evidence.filter((e) => e.id !== id),
		assets: data.assets
			.map((a) => ({
				...a,
				evidenceIds: a.evidenceIds.filter((e) => e !== id),
			}))
			.filter((a) => a.evidenceIds.length),
	});
}
export function parseCrtResult(
	payload: unknown,
	query: ReconQuery,
): Pick<ReconResult, "facts" | "warnings" | "assets" | "issues"> {
	query = validateReconQuery(query);
	if (!Array.isArray(payload) || payload.length > 30000)
		throw new Error("crt.sh devolvió una lista inválida o demasiado grande.");
	const assets = new Set<string>();
	let wildcards = 0;
	for (const row of payload) {
		const record = object(row, "Certificado");
		if (
			typeof record.name_value !== "string" ||
			record.name_value.length > 30000
		)
			throw new Error("Nombre de certificado inválido.");
		for (const name of record.name_value.split(/\s+/).filter(Boolean)) {
			if (name.startsWith("*.")) {
				wildcards++;
				continue;
			}
			let normalized: string;
			try {
				normalized = publicDomain(name);
			} catch {
				continue;
			}
			if (
				normalized === query.domain ||
				(query.subdomains && normalized.endsWith(`.${query.domain}`))
			)
				assets.add(normalized);
		}
	}
	const warnings = [
		"Un certificado es evidencia histórica: no confirma que el host exista hoy ni que esté autorizado.",
	];
	if (wildcards)
		warnings.push(
			`${wildcards} nombres comodín omitidos: un patrón *.dominio no identifica un host concreto.`,
		);
	if (assets.size > MAX_QUERY_ASSETS)
		warnings.push(
			`Resultado parcial: ${assets.size} nombres únicos; se conservan los primeros ${MAX_QUERY_ASSETS}. Reduce la consulta.`,
		);
	return {
		facts: [
			{ label: "Certificados recibidos", value: String(payload.length) },
			{ label: "Nombres únicos de la consulta", value: String(assets.size) },
		],
		warnings,
		assets: [...assets].sort().slice(0, MAX_QUERY_ASSETS),
	};
}
export function parseRdapResult(
	payload: unknown,
	domain: string,
): Pick<ReconResult, "facts" | "warnings" | "assets" | "issues"> {
	domain = publicDomain(domain);
	const record = object(payload, "RDAP");
	if (
		typeof record.ldhName !== "string" ||
		normalizeScopeEntry(record.ldhName) !== domain
	)
		throw new Error("RDAP devolvió un dominio distinto del solicitado.");
	const facts = [{ label: "Dominio registrado", value: domain }];
	const names = new Set<string>();
	for (const value of list(record.nameservers ?? [], 100, "Nameservers")) {
		const ns = object(value, "Nameserver");
		if (typeof ns.ldhName === "string") {
			try {
				names.add(normalizeScopeEntry(ns.ldhName));
			} catch {
				/* Ignore unsupported names. */
			}
		}
	}
	if (names.size)
		facts.push({
			label: "Servidores DNS publicados",
			value: [...names].join("\n"),
		});
	for (const item of list(record.events ?? [], 30, "Eventos")) {
		const event = object(item, "Evento");
		if (
			typeof event.eventAction === "string" &&
			typeof event.eventDate === "string"
		)
			facts.push({
				label: event.eventAction.slice(0, 200),
				value: date(event.eventDate),
			});
	}
	const statuses = list(record.status ?? [], 30, "Estados").map((s) =>
		text(s, "Estado", 200),
	);
	if (statuses.length)
		facts.push({ label: "Estado del registro", value: statuses.join(", ") });
	for (const item of list(record.entities ?? [], 100, "Entidades")) {
		const entity = object(item, "Entidad");
		if (
			Array.isArray(entity.roles) &&
			entity.roles.includes("registrar") &&
			typeof entity.handle === "string"
		)
			facts.push({
				label: "Identificador del registrador",
				value: entity.handle.slice(0, 200),
			});
	}
	return {
		facts: facts.slice(0, 100),
		warnings: [
			"Los servidores DNS pueden pertenecer a terceros; su aparición no amplía el alcance.",
			"Se omiten contactos personales y el JSON crudo del registro.",
		],
		assets: [domain, ...names],
	};
}
export function parseDnsResult(
	payload: unknown,
	domain: string,
): Pick<ReconResult, "facts" | "warnings" | "assets" | "issues"> {
	domain = publicDomain(domain);
	const response = object(payload, "DNS");
	const rows = list(response.rows, 7, "Registros DNS");
	const types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"];
	const seen = new Set<string>();
	const assets = new Set<string>();
	const facts: ReconResult["facts"] = [];
	const warnings = [
		"Los registros corresponden al nombre exacto consultado; no se consultan automáticamente el dominio padre ni los hosts encontrados.",
		"Las IP y servidores publicados son candidatos; pueden pertenecer a proveedores y no amplían el alcance.",
	];
	const issues: NonNullable<ReconResult["issues"]> = [];
	let failures = 0;
	for (const value of rows) {
		const row = object(value, "Registro DNS");
		const type = text(row.type, "Tipo DNS", 10);
		if (!types.includes(type) || seen.has(type))
			throw new Error("Tipos DNS inválidos o duplicados.");
		seen.add(type);
		const values = list(row.values, 100, "Respuestas DNS");
		if (row.error !== undefined) {
			const code = text(row.error, "Error DNS", 100);
			if (values.length) throw new Error("Respuesta DNS contradictoria.");
			if (!["ENODATA", "ENOTFOUND"].includes(code)) {
				failures++;
				warnings.push(`${type}: consulta no disponible (${code}).`);
				issues.push({ stage: `DNS ${type}`, error: code });
			}
			facts.push({
				label: type,
				value: ["ENODATA", "ENOTFOUND"].includes(code)
					? `Sin registros (${code})`
					: `Consulta no disponible (${code})`,
			});
			continue;
		}
		const formatted = values.map((entry) => {
			if (type === "A" || type === "AAAA") {
				const ip = text(entry, type, 100);
				if (
					ip.includes("/") ||
					addressRange(ip)?.kind !== (type === "A" ? "ipv4" : "ipv6")
				)
					throw new Error("Dirección DNS inválida.");
				assets.add(normalizeScopeEntry(ip));
				return ip;
			}
			if (type === "NS" || type === "CNAME") {
				const name = publicDomain(text(entry, type, 253));
				assets.add(name);
				return name;
			}
			if (type === "TXT")
				return list(entry, 100, "Fragmentos TXT")
					.map((chunk) => text(chunk, "TXT", 4096, true))
					.join("");
			const record = object(entry, type);
			if (type === "MX") {
				if (
					!Number.isInteger(record.priority) ||
					Number(record.priority) < 0 ||
					Number(record.priority) > 65535
				)
					throw new Error("Prioridad MX inválida.");
				if (record.exchange === "" || record.exchange === ".")
					return `${record.priority} . (Null MX: no recibe correo)`;
				const name = publicDomain(text(record.exchange, "Servidor MX", 253));
				assets.add(name);
				return `${record.priority} ${name}`;
			}
			return `NS ${text(record.nsname, "NS SOA", 253)} · serial ${text(String(record.serial), "Serial SOA", 100)}`;
		});
		if (values.length) assets.add(domain);
		facts.push({
			label: type,
			value: formatted.join("\n").slice(0, 8192) || "Sin registros",
		});
	}
	if (seen.size !== 7) throw new Error("La respuesta DNS está incompleta.");
	if (failures === 7)
		throw new Error(
			"No se pudo consultar DNS desde Kali. Revisa su conectividad y resolvedor.",
		);
	facts.push({
		label: "Resolvedores usados en Kali",
		value: list(response.resolvers, 20, "Resolvedores")
			.map((value) => text(value, "Resolvedor", 100))
			.join(", "),
	});
	return {
		facts,
		warnings,
		issues,
		assets: [...assets].sort().slice(0, MAX_QUERY_ASSETS),
	};
}

export function parsePtrResult(
	payload: unknown,
	address: string,
): Pick<ReconResult, "facts" | "warnings" | "assets" | "issues"> {
	address = reconTarget(address);
	if (!addressRange(address)) throw new Error("DNS inverso requiere una IP.");
	const response = object(payload, "DNS inverso");
	if (response.address !== address)
		throw new Error("Respuesta DNS inversa de una IP distinta.");
	const values = list(response.names, 100, "Nombres PTR");
	const names = values.map((value) => {
		const name = normalizeScopeEntry(text(value, "Nombre PTR", 253));
		if (addressRange(name)) throw new Error("Nombre PTR inválido.");
		return name;
	});
	let result = [...new Set(names)].join("\n") || "Sin registros PTR";
	if (response.error !== undefined) {
		const code = text(response.error, "Error PTR", 100);
		if (names.length) throw new Error("Respuesta PTR contradictoria.");
		if (!["ENODATA", "ENOTFOUND"].includes(code))
			throw new Error(`No se pudo consultar DNS inverso desde Kali (${code}).`);
		result = `Sin registros PTR (${code})`;
	}
	return {
		facts: [
			{ label: "IP consultada", value: address },
			{ label: "PTR", value: result.slice(0, 8192) },
			{
				label: "Resolvedores usados en Kali",
				value: list(response.resolvers, 20, "Resolvedores")
					.map((value) => text(value, "Resolvedor", 100))
					.join(", "),
			},
		],
		warnings: [
			"Los nombres PTR son candidatos, pueden ser internos o estar desactualizados. No se resuelven ni contactan automáticamente y no amplían el alcance.",
		],
		issues: [],
		assets: names.length ? [address, ...new Set(names)] : [],
	};
}

export function parseTlsResult(
	payload: unknown,
	domain: string,
	address: string,
): Pick<ReconResult, "facts" | "warnings" | "assets" | "issues"> {
	domain = reconTarget(domain);
	const cert = object(payload, "Certificado TLS");
	if (cert.address !== address || typeof cert.authorized !== "boolean")
		throw new Error("Respuesta TLS inválida o destino distinto.");
	const warnings = [
		"Lectura activa: se realizó una conexión TLS al servicio. Los nombres del certificado no amplían el alcance.",
	];
	if (addressRange(domain))
		warnings.push(
			"Conexión por IP sin SNI: el servicio puede presentar su certificado predeterminado. Se comprueba la identidad contra la IP, no contra un dominio.",
		);
	if (!cert.authorized)
		warnings.push(
			`La cadena TLS no fue validada: ${text(cert.authorizationError, "Validación TLS", 2048, true)}.`,
		);
	if (cert.hostnameError)
		warnings.push(text(cert.hostnameError, "Nombre TLS", 2048));
	const issues: NonNullable<ReconResult["issues"]> = [];
	if (!cert.authorized)
		issues.push({
			stage: "Validar cadena TLS",
			error: String(cert.authorizationError || "Cadena no validada"),
		});
	if (cert.hostnameError)
		issues.push({
			stage: "Validar nombre TLS",
			error: String(cert.hostnameError),
		});
	const assets = new Set([domain, address]);
	const san = text(cert.san, "SAN", 8192, true);
	for (const match of san.matchAll(/(?:^|,\s*)DNS:([^,]+)/g)) {
		if (match[1].startsWith("*.")) continue;
		try {
			assets.add(publicDomain(match[1]));
		} catch {
			/* Unsupported SAN. */
		}
	}
	const facts = [
		["IP contactada", address],
		["Nombre común", cert.subject],
		["Emisor", cert.issuer],
		["Nombres SAN", san],
		["Válido desde", cert.validFrom],
		["Válido hasta", cert.validTo],
		["Huella SHA256", cert.fingerprint],
		["Protocolo TLS", cert.protocol],
	].map(([label, value]) => ({
		label: String(label),
		value: text(value, String(label), 8192, true),
	}));
	return {
		facts,
		warnings,
		issues,
		assets: [...assets].slice(0, MAX_QUERY_ASSETS),
	};
}

export function scopeManualResult(
	content: string,
	label: string,
	sourceUrl: string,
	observedAt: string,
	scopeRevision?: number,
): ReconResult {
	if (content.length > 150000)
		throw new Error("La lista de activos es demasiado grande.");
	const assets = [
		...new Set(
			content
				.split(/[\s,;]+/)
				.filter(Boolean)
				.map(normalizeScopeEntry),
		),
	];
	if (assets.length > MAX_QUERY_ASSETS)
		throw new Error("Se admiten hasta 500 activos por evidencia manual.");
	return {
		source: "manual",
		query: text(label, "Título", 1024),
		sourceUrl: safeSourceUrl(sourceUrl),
		retrievedAt: date(observedAt),
		scopeRevision,
		assets,
		facts: [{ label: "Activos aportados", value: String(assets.length) }],
		warnings: [
			"La información aportada requiere revisión; no confirma propiedad ni autorización de los activos.",
		],
	};
}
