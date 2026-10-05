import { type KaliExecutor, validateExecutor } from "./kali.ts";
import { quoteArg } from "./nmap-command.ts";
import { redactText } from "./redaction.ts";
import type { ObservedPort } from "./results.ts";
import {
	addressRange,
	approvalIssues,
	normalizeScopeEntry,
	portRanges,
	type ScopePlan,
	targetDecision,
} from "./scope.ts";
import type { WorkspaceProject } from "./storage.ts";
import { parseNiktoTarget } from "./web-target.mjs";

export const analysisTools = {
	searchsploit: "SearchSploit",
	cve: "cve-search local",
	nikto: "Nikto",
	testssl: "testssl.sh",
	trivy: "Trivy",
} as const;
export type AnalysisTool = keyof typeof analysisTools;
export const reviewStates = {
	candidate: "Candidata",
	confirmed: "Confirmada por revisión",
	discarded: "Descartada",
	resolved: "Corregida",
} as const;
export type Finding = {
	id: string;
	title: string;
	target: string;
	port?: number;
	source: string;
	cves: string[];
	severity: string;
	description: string;
	recommendation: string;
	status: keyof typeof reviewStates;
	note: string;
	evidenceId: string;
	date: string;
};
export type AnalysisEvidence = {
	id: string;
	tool: AnalysisTool | "manual";
	target: string;
	port?: number;
	query: string;
	date: string;
	raw: string;
	warnings: string[];
	error: string;
	scopeRevision?: number;
	executor?: KaliExecutor;
};
export type AnalysisData = {
	version: 1;
	evidence: AnalysisEvidence[];
	findings: Finding[];
};
export const emptyAnalysis = (): AnalysisData => ({
	version: 1,
	evidence: [],
	findings: [],
});
export type AnalysisQuery = {
	tool: AnalysisTool;
	target: string;
	port: number;
	tls: boolean;
	product: string;
	vendor: string;
	version: string;
	cve: string;
	path: string;
	timeoutSeconds: number;
};
export const defaultAnalysisQuery = (): AnalysisQuery => ({
	tool: "searchsploit",
	target: "",
	port: 443,
	tls: true,
	product: "",
	vendor: "",
	version: "",
	cve: "",
	path: "",
	timeoutSeconds: 60,
});
export function analysisQueryWithPort(
	q: AnalysisQuery,
	port: number,
): AnalysisQuery {
	const tls = port === 80 ? false : port === 443 ? true : q.tls;
	return analysisQueryWithTransport(q, port, tls);
}
function analysisQueryWithTransport(
	q: AnalysisQuery,
	port: number,
	tls: boolean,
): AnalysisQuery {
	let target = q.target;
	if (q.tool === "nikto" && /^https?:\/\//i.test(target)) {
		try {
			const url = new URL(target);
			url.protocol = tls ? "https:" : "http:";
			url.port = String(port);
			target = url.toString();
		} catch {
			/* Preserve input while editing. */
		}
	}
	return { ...q, target, port, tls };
}
export function analysisQueryWithTarget(
	q: AnalysisQuery,
	target: string,
): AnalysisQuery {
	const next = { ...q, target };
	if (q.tool === "nikto" && /^https?:\/\//i.test(target)) {
		try {
			const web = parseNiktoTarget(next);
			return { ...next, port: web.port, tls: web.tls };
		} catch {
			/* Show validation feedback when input is complete. */
		}
	}
	return next;
}
export function analysisQueryWithTls(
	q: AnalysisQuery,
	tls: boolean,
): AnalysisQuery {
	return analysisQueryWithTransport(
		q,
		tls && q.port === 80 ? 443 : !tls && q.port === 443 ? 80 : q.port,
		tls,
	);
}
export function validateAnalysisQuery(value: unknown): AnalysisQuery {
	const item = obj(value);
	if (!Object.hasOwn(analysisTools, String(item.tool)))
		throw new Error("Herramienta no compatible.");
	if (
		typeof item.tls !== "boolean" ||
		!Number.isInteger(item.port) ||
		Number(item.port) < 1 ||
		Number(item.port) > 65535 ||
		!Number.isInteger(item.timeoutSeconds) ||
		Number(item.timeoutSeconds) < 5 ||
		Number(item.timeoutSeconds) > 180
	)
		throw new Error("Puerto, TLS o timeout inválido (5–180 segundos).");
	const q: AnalysisQuery = {
		tool: item.tool as AnalysisTool,
		target: txt(item.target, item.tool === "nikto" ? 1000 : 255),
		port: Number(item.port),
		tls: item.tls,
		product: txt(item.product, 200),
		vendor: txt(item.vendor, 200),
		version: txt(item.version, 100),
		cve: txt(item.cve, 30).toUpperCase(),
		path: txt(item.path, 1000),
		timeoutSeconds: Number(item.timeoutSeconds),
	};
	if (q.tool === "nikto") {
		const web = parseNiktoTarget(q);
		normalizeScopeEntry(web.host);
		q.port = web.port;
		q.tls = web.tls;
	}
	if (q.cve && !/^CVE-\d{4}-\d{4,}$/.test(q.cve))
		throw new Error("Identificador CVE inválido.");
	if (["searchsploit", "cve"].includes(q.tool) && !q.cve && !q.product.trim())
		throw new Error("Escribe un producto o CVE.");
	if (q.tool === "cve" && !q.cve && !q.vendor.trim())
		throw new Error(
			"Indica el proveedor tal como figura en la base CPE, o busca un CVE concreto.",
		);
	if (
		[q.product, q.version].some((v) => v.startsWith("-") || /[\r\n\0]/.test(v))
	)
		throw new Error("Producto o versión inválidos.");
	if (
		q.tool === "trivy" &&
		(!q.path.startsWith("/") || /[\r\n\0]/.test(q.path))
	)
		throw new Error("Usa una ruta absoluta de Kali para Trivy.");
	return q;
}
export function analysisQueryIssues(
	q: AnalysisQuery,
	plan?: ScopePlan,
	now = Date.now(),
): string[] {
	if (q.tool !== "nikto" && q.tool !== "testssl") return [];
	if (!plan) return ["Aprueba un plan para probar servicios."];
	const issues = approvalIssues(plan, now);
	if (plan.status !== "approved" || !plan.approvalAttested || !plan.approvedAt)
		issues.push("El plan debe estar aprobado.");
	if (!plan.analysisTools?.[q.tool])
		issues.push(
			`Autoriza ${analysisTools[q.tool]} en Alcance y planificación y vuelve a aprobar el plan.`,
		);
	if (
		now < Date.parse(plan.windowStart) ||
		now + q.timeoutSeconds * 1000 > Date.parse(plan.windowEnd) ||
		q.timeoutSeconds > plan.maxDurationSeconds
	)
		issues.push("La prueba excede la ventana o duración autorizada.");
	let target = q.target;
	let port = q.port;
	if (q.tool === "nikto") {
		try {
			const web = parseNiktoTarget(q);
			target = normalizeScopeEntry(web.host);
			port = web.port;
		} catch (e) {
			issues.push(e instanceof Error ? e.message : "URL inválida.");
			return issues;
		}
	}
	const range = addressRange(target);
	if (
		q.tool !== "nikto" &&
		(!range || range.count !== 1n || target.includes("/"))
	)
		issues.push(
			"Selecciona una IP concreta del inventario; los nombres DNS no se ejecutan para evitar ampliar el alcance.",
		);
	const decision = targetDecision(target, plan);
	if (!decision.allowed) issues.push(decision.reason);
	if (!portRanges(plan.allowedPorts).some(([a, b]) => port >= a && port <= b))
		issues.push("Puerto fuera del alcance.");
	return issues;
}
export function analysisResolvedAddress(
	q: AnalysisQuery,
	plan: ScopePlan,
	resolved: Record<string, string[]>,
): string {
	const host = parseNiktoTarget(q).host;
	const domain = !addressRange(host);
	const excludedNames = plan.excludes.filter((entry) => !addressRange(entry));
	for (const name of [...(domain ? [host] : []), ...excludedNames]) {
		if (!Array.isArray(resolved[name]) || !resolved[name].length)
			throw new Error(
				`No se pudo resolver ${name} en Kali para verificar el alcance.`,
			);
		for (const ip of resolved[name])
			if (
				typeof ip !== "string" ||
				ip.includes("/") ||
				addressRange(ip)?.count !== 1n
			)
				throw new Error("Kali devolvió una dirección DNS inválida.");
	}
	const addresses = domain ? resolved[host] : [host];
	const effectivePlan = {
		...plan,
		includes: domain ? [...plan.includes, ...addresses] : plan.includes,
		excludes: [
			...plan.excludes,
			...excludedNames.flatMap((name) => resolved[name]),
		],
	};
	if (!targetDecision(host, plan).allowed)
		throw new Error("El dominio o IP no está incluido en el alcance aprobado.");
	for (const ip of addresses)
		if (!targetDecision(ip, effectivePlan).allowed)
			throw new Error(
				`El destino ${host} resuelve a ${ip}, fuera del alcance o excluido.`,
			);
	return addresses.find((ip) => !ip.includes(":")) ?? addresses[0];
}
export function analysisInventory(project: WorkspaceProject) {
	// Última observación por servicio, con su ejecución de origen; no combina versiones antiguas.
	const rows = new Map<
		string,
		{
			target: string;
			hostname: string;
			observed: ObservedPort;
			runId: string;
			date: string;
		}
	>();
	for (const run of [...(project.lastRuns ?? [])].sort((a, b) =>
		a.date.localeCompare(b.date),
	)) {
		for (const host of run.hosts ?? []) {
			if (host.status === "down") {
				for (const [key, row] of rows)
					if (row.target === host.address) rows.delete(key);
				continue;
			}
			for (const port of host.ports)
				rows.set(`${host.address}|${port.protocol}|${port.port}`, {
					target: host.address,
					hostname: host.hostname ?? "",
					observed: port,
					runId: run.id,
					date: run.date,
				});
		}
	}
	return [...rows.values()].filter((r) => r.observed.state === "open");
}
export function findingPriority(f: Finding) {
	const severity = f.severity.toUpperCase();
	const score = /CVSS\s+(\d+(?:\.\d+)?)/.exec(severity);
	return score
		? Math.min(10, Number(score[1]))
		: ((
				{ CRITICAL: 10, HIGH: 8, MEDIUM: 5, LOW: 2, INFO: 0 } as Record<
					string,
					number
				>
			)[severity] ?? 0);
}
export function toolRecommendations(
	port: ObservedPort,
): { tool: AnalysisTool; reason: string }[] {
	const result: { tool: AnalysisTool; reason: string }[] = [];
	if (port.product)
		result.push(
			{
				tool: "searchsploit",
				reason: "Buscar referencias del producto y versión observados.",
			},
			{
				tool: "cve",
				reason: "Consultar CVE y revisar rangos afectados y condiciones.",
			},
		);
	if (port.protocol !== "tcp") return result;
	const name = `${port.service} ${port.product ?? ""}`.toLowerCase();
	if (/http|apache|nginx|iis|tomcat/.test(name))
		result.push({
			tool: "nikto",
			reason: "Revisar exposición y configuración del servidor web.",
		});
	if (
		/ssl|tls|https/.test(name) ||
		[443, 8443, 636, 993, 995, 465].includes(port.port)
	)
		result.push({
			tool: "testssl",
			reason:
				"Verificar protocolos, cifrados y condiciones TLS; aquí se admiten servicios con TLS directo.",
		});
	return result;
}
export function analysisCommand(q: AnalysisQuery): string {
	let web: ReturnType<typeof parseNiktoTarget> | undefined;
	if (q.tool === "nikto") {
		try {
			web = parseNiktoTarget(q);
		} catch (e) {
			return e instanceof Error ? e.message : "URL inválida.";
		}
	}
	const host = q.target.includes(":") ? `[${q.target}]` : q.target;
	const args =
		q.tool === "searchsploit"
			? [
					"searchsploit",
					"-j",
					...(q.cve
						? ["--cve", q.cve]
						: [q.product, ...(q.version ? [q.version] : [])]),
				]
			: q.tool === "cve"
				? [
						"Consulta local",
						`http://127.0.0.1:5000/api/${q.cve ? `cve/${q.cve}` : `search/${encodeURIComponent(q.vendor)}/${encodeURIComponent(q.product)}`}`,
					]
				: q.tool === "nikto"
					? [
							"nikto",
							"-h",
							`${web?.tls ? "https" : "http"}://${web?.host.includes(":") ? `[${web.host}]` : web?.host}:${web?.port}`,
							web?.tls ? "-ssl" : "-nossl",
							...(web?.root ? ["-root", web.root] : []),
							"-nointeractive",
							"-ask",
							"no",
							"-nolookup",
							"-nocheck",
							"-Pause",
							"1",
							"-Tuning",
							"123b",
							"-maxtime",
							`${Math.max(1, q.timeoutSeconds - 15)}s`,
							"-timeout",
							"10",
							"-Format",
							"json",
							"-output",
							"<reporte temporal>",
						]
					: q.tool === "testssl"
						? [
								"testssl",
								"--quiet",
								"--warnings",
								"batch",
								"--color",
								"0",
								"--connect-timeout",
								"5",
								"--openssl-timeout",
								"5",
								"--jsonfile",
								"<reporte temporal>",
								`${host}:${q.port}`,
							]
						: [
								"trivy",
								"fs",
								"--scanners",
								"vuln",
								"--offline-scan",
								"--skip-db-update",
								"--skip-java-db-update",
								"--skip-check-update",
								"--skip-version-check",
								"--format",
								"json",
								"--timeout",
								`${q.timeoutSeconds}s`,
								"--",
								q.path,
							];
	return args.map(quoteArg).join(" ");
}
function obj(v: unknown): Record<string, unknown> {
	if (!v || typeof v !== "object" || Array.isArray(v))
		throw new Error("Datos de análisis inválidos.");
	return v as Record<string, unknown>;
}
function txt(v: unknown, max = 2000): string {
	if (typeof v !== "string" || v.length > max)
		throw new Error("Texto de análisis inválido o demasiado extenso.");
	return redactText(v);
}
function list(v: unknown, max: number): unknown[] {
	if (!Array.isArray(v) || v.length > max)
		throw new Error("Lista de análisis demasiado extensa o inválida.");
	return v;
}
function date(v: unknown) {
	const d = txt(v, 100);
	if (!Number.isFinite(Date.parse(d))) throw new Error("Fecha inválida.");
	return d;
}
function optionalPort(v: unknown) {
	if (v === undefined) return undefined;
	if (!Number.isInteger(v) || Number(v) < 1 || Number(v) > 65535)
		throw new Error("Puerto inválido.");
	return Number(v);
}
export function validateAnalysisData(value: unknown): AnalysisData {
	const data = obj(value);
	if (data.version !== 1) throw new Error("Versión de análisis inválida.");
	const evidence = list(data.evidence, 30).map((v): AnalysisEvidence => {
		const e = obj(v);
		if (e.tool !== "manual" && !Object.hasOwn(analysisTools, String(e.tool)))
			throw new Error("Fuente inválida.");
		return {
			id: txt(e.id, 128),
			tool: e.tool as AnalysisEvidence["tool"],
			target: txt(e.target, 1000),
			port: optionalPort(e.port),
			query: txt(e.query, 4000),
			date: date(e.date),
			raw: txt(e.raw, 60000),
			warnings: list(e.warnings, 20).map((v) => txt(v, 2000)),
			error: txt(e.error, 4000),
			scopeRevision:
				e.scopeRevision === undefined
					? undefined
					: positiveRevision(e.scopeRevision),
			executor:
				e.executor === undefined ? undefined : validateExecutor(e.executor),
		};
	});
	const findings = list(data.findings, 500).map((v): Finding => {
		const f = obj(v);
		if (!Object.hasOwn(reviewStates, String(f.status)))
			throw new Error("Estado inválido.");
		const finding = {
			id: txt(f.id, 128),
			title: txt(f.title, 1000),
			target: txt(f.target, 1000),
			port: optionalPort(f.port),
			source: txt(f.source, 200),
			cves: list(f.cves, 50).map((v) => txt(v, 30)),
			severity: txt(f.severity, 100),
			description: txt(f.description, 4000),
			recommendation: txt(f.recommendation, 4000),
			status: f.status as Finding["status"],
			note: txt(f.note, 4000),
			evidenceId: txt(f.evidenceId, 128),
			date: date(f.date),
		};
		if (
			!evidence.some((e) => e.id === finding.evidenceId) ||
			finding.cves.some((c) => !/^CVE-\d{4}-\d{4,}$/.test(c))
		)
			throw new Error("Hallazgo sin evidencia o CVE inválido.");
		if (finding.status === "confirmed" && !finding.note.trim())
			throw new Error("Documenta la validación para confirmar un hallazgo.");
		return finding;
	});
	for (const items of [evidence, findings])
		if (
			items.some((e) => !e.id) ||
			new Set(items.map((e) => e.id)).size !== items.length
		)
			throw new Error("IDs de análisis duplicados o vacíos.");
	return { version: 1, evidence, findings };
}
function positiveRevision(v: unknown) {
	if (!Number.isSafeInteger(v) || Number(v) < 1)
		throw new Error("Revisión inválida.");
	return Number(v);
}
export function cveIds(text: string) {
	return [
		...new Set(
			text.match(/CVE-\d{4}-\d{4,}/gi)?.map((v) => v.toUpperCase()) ?? [],
		),
	].slice(0, 50);
}
export function parseAnalysisReport(
	tool: AnalysisTool,
	raw: string,
): Omit<
	Finding,
	| "id"
	| "target"
	| "port"
	| "source"
	| "evidenceId"
	| "date"
	| "status"
	| "note"
>[] {
	const data: unknown = JSON.parse(raw);
	const result: ReturnType<typeof parseAnalysisReport> = [];
	const add = (
		title: unknown,
		description: unknown,
		severity: unknown = "Sin clasificar",
		recommendation: unknown = "Verificar versión, condiciones y parches antes de confirmar.",
		ids = "",
	) => {
		if (result.length >= 500)
			throw new Error(
				"El reporte supera 500 hallazgos. Reduce la consulta o conserva la salida como evidencia manual.",
			);
		const text = (v: unknown, max: number) =>
			redactText(String(v ?? "")).slice(0, max);
		result.push({
			title: text(title, 1000),
			description: text(description, 4000),
			severity: text(severity, 100),
			recommendation: text(recommendation, 4000),
			cves: cveIds(`${title} ${description} ${ids}`),
		});
	};
	if (tool === "searchsploit") {
		const d = obj(data);
		if (!Array.isArray(d.RESULTS_EXPLOIT))
			throw new Error("Formato SearchSploit no reconocido.");
		for (const item of d.RESULTS_EXPLOIT) {
			const e = obj(item);
			if (typeof e.Title !== "string")
				throw new Error("Entrada SearchSploit incompleta.");
			add(
				e.Title,
				`EDB ${e["EDB-ID"] ?? ""} · ${e.Platform ?? ""} · ${e.Type ?? ""} · ${e.Path ?? ""}`,
				"Sin clasificar",
				undefined,
				String(e.Codes ?? ""),
			);
		}
	} else if (tool === "cve") {
		const rows = Array.isArray(data)
			? data
			: Array.isArray(obj(data).data)
				? (obj(data).data as unknown[])
				: [data];
		for (const item of rows) {
			const e = obj(item);
			if (typeof e.id !== "string" || !/^CVE-/.test(e.id))
				throw new Error("Formato cve-search no reconocido.");
			add(
				e.id,
				e.summary,
				e.cvss !== undefined ? `CVSS ${e.cvss}` : "Sin clasificar",
				undefined,
				e.id,
			);
		}
	} else if (tool === "trivy") {
		const d = obj(data);
		if (!Array.isArray(d.Results) && d.SchemaVersion === undefined)
			throw new Error("Formato Trivy no reconocido.");
		for (const row of (d.Results ?? []) as unknown[]) {
			const r = obj(row);
			for (const item of (r.Vulnerabilities ?? []) as unknown[]) {
				const e = obj(item);
				add(
					`${e.VulnerabilityID} · ${e.PkgName} ${e.InstalledVersion}`,
					e.Description ?? e.Title,
					e.Severity,
					e.FixedVersion
						? `Revisar actualización a ${e.FixedVersion} y el aviso del proveedor.`
						: undefined,
					String(e.VulnerabilityID ?? ""),
				);
			}
		}
	} else if (tool === "testssl") {
		if (!Array.isArray(data))
			throw new Error("Se requiere JSON plano de testssl.sh.");
		for (const item of data) {
			const e = obj(item);
			if (
				typeof e.id !== "string" ||
				typeof e.finding !== "string" ||
				typeof e.severity !== "string"
			)
				throw new Error("Entrada testssl.sh incompleta.");
			if (!["OK", "INFO", "DEBUG"].includes(String(e.severity).toUpperCase()))
				add(e.id, e.finding, e.severity, undefined, String(e.cve ?? ""));
		}
	} else {
		const rows = Array.isArray(data) ? data : [data];
		for (const row of rows) {
			const r = obj(row);
			if (!Array.isArray(r.vulnerabilities))
				throw new Error("Formato Nikto no reconocido.");
			for (const item of r.vulnerabilities) {
				const e = obj(item);
				if (e.id === "FAIL") continue;
				add(
					`Nikto ${e.id ?? ""} · ${e.url ?? ""}`,
					`${e.msg ?? e.message ?? ""}${e.references ? `\nReferencias: ${Array.isArray(e.references) ? e.references.join(", ") : String(e.references)}` : ""}`,
					"Sin clasificar",
					"Revisar la respuesta HTTP y configuración antes de confirmar.",
				);
			}
		}
	}
	return result;
}
export function appendAnalysis(
	data: AnalysisData | undefined,
	evidence: AnalysisEvidence,
	found: ReturnType<typeof parseAnalysisReport>,
): AnalysisData {
	const existing = data ?? emptyAnalysis();
	if (
		existing.findings.length + found.length > 500 ||
		existing.evidence.length >= 30
	)
		throw new Error(
			"Límite de 500 hallazgos o 30 evidencias. Exporta y elimina evidencias antiguas antes de guardar.",
		);
	return validateAnalysisData({
		version: 1,
		evidence: [evidence, ...existing.evidence],
		findings: [
			...found.map((f) => ({
				...f,
				id: crypto.randomUUID(),
				target: evidence.target,
				port: evidence.port,
				source: evidence.tool,
				evidenceId: evidence.id,
				date: evidence.date,
				status: "candidate",
				note: "",
			})),
			...existing.findings,
		],
	});
}
export function analysisMarkdown(project: WorkspaceProject) {
	const data = project.analysis ?? emptyAnalysis();
	return [
		`# Análisis — ${project.name}`,
		"Coincidencias candidatas; confirmar aplicabilidad, condiciones y parches. Sin resultados no significa sin vulnerabilidades.",
		`## Inventario\n${analysisInventory(project)
			.map(
				(r) =>
					`- ${r.target}:${r.observed.port}/${r.observed.protocol} · ${r.observed.service} · ${r.observed.product ?? ""} ${r.observed.version ?? ""} · ${r.date} · ejecución ${r.runId}`,
			)
			.join("\n")}`,
		...data.findings.map(
			(f) =>
				`## ${f.title}\n\n${f.target}:${f.port ?? "—"} · ${f.severity} · ${reviewStates[f.status]}\n\n${f.description}\n\nCVE: ${f.cves.join(", ") || "Sin asociación"}\n\n${f.recommendation}\n\nRevisión: ${f.note || "Pendiente"}\n\nEvidencia: ${f.evidenceId}`,
		),
		...data.evidence.map(
			(e) =>
				`## Evidencia ${e.id}\n\n${e.date} · ${e.tool} · ${e.target} · revisión ${e.scopeRevision ?? "—"} · ejecutor ${e.executor ? JSON.stringify(e.executor) : "importación manual"}\n\n${e.query}\n\n${e.warnings.join("\n")}\n${e.error}\n\n${e.raw
					.split("\n")
					.map((line) => `    ${line}`)
					.join("\n")}`,
		),
	].join("\n\n");
}
