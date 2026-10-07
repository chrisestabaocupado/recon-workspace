import { createServerFn } from "@tanstack/react-start";
import type { Client } from "ssh2";
import {
	type AnalysisEvidence,
	analysisCommand,
	analysisQueryIssues,
	analysisResolvedAddress,
	parseAnalysisReport,
	validateAnalysisQuery,
} from "../lib/analysis.ts";
import { executorIdentity, type KaliAccess } from "../lib/kali.ts";
import nvdSource from "../lib/nvd.mjs?raw";
import { redactText } from "../lib/redaction.ts";
import {
	addressRange,
	type ScopePlan,
	validateScopePlan,
} from "../lib/scope.ts";
import { parseNiktoTarget } from "../lib/web-target.mjs";
import webTargetSource from "../lib/web-target.mjs?raw";
import { kaliVerifications } from "./kali-access.ts";
import remoteSource from "./remote-analysis.mjs?raw";
import { connectSsh, execJsonInput } from "./ssh.ts";

let active = false;
let lastNvdRequest = 0;
const remoteProgram = remoteSource
	.replace(
		'import { parseNiktoTarget } from "../lib/web-target.mjs";',
		webTargetSource.replace(
			"export function parseNiktoTarget",
			"function parseNiktoTarget",
		),
	)
	.replace(
		'import { nvdUrl } from "../lib/nvd.mjs";',
		nvdSource.replaceAll("export function", "function"),
	);
async function remote(
	access: KaliAccess,
	payload: object,
	seconds: number,
	plan?: ScopePlan,
) {
	if (active)
		throw new Error(
			"Ya hay una operación de análisis en Kali. Espera su finalización.",
		);
	if (
		record(payload).operation === "run" &&
		record(record(payload).query).tool === "nvd"
	) {
		if (Date.now() - lastNvdRequest < 6000)
			throw new Error("Espera 6 segundos entre consultas a NVD.");
		lastNvdRequest = Date.now();
	}
	active = true;
	let connection: Client | undefined;
	const deadline = Date.now() + seconds * 1000;
	const signal = AbortSignal.timeout((seconds + 10) * 1000);
	const abort = () => connection?.end();
	signal.addEventListener("abort", abort, { once: true });
	try {
		connection = await connectSsh(access.ssh, signal);
		const request = record(payload);
		if (request.operation === "run") {
			const query = validateAnalysisQuery(request.query);
			if (query.tool === "nikto" && plan) {
				const host = parseNiktoTarget(query).host;
				const names = [
					...new Set(
						[host, ...plan.excludes].filter((name) => !addressRange(name)),
					),
				];
				if (names.length > 64)
					throw new Error(
						"El plan contiene demasiados dominios para comprobar el alcance (máximo 64).",
					);
				const resolved = names.length
					? (record(
							await execJsonInput(
								connection,
								'const {lookup}=await import("node:dns/promises");let t="";for await(const c of process.stdin)t+=c;const {names}=JSON.parse(t);console.log(JSON.stringify(Object.fromEntries(await Promise.all(names.map(async n=>[n,(await lookup(n,{all:true})).map(r=>r.address)])))))',
								{ names },
								signal,
								100000,
							),
						) as Record<string, string[]>)
					: {};
				payload = {
					...payload,
					pinnedAddress: analysisResolvedAddress(query, plan, resolved),
				};
			}
			const remaining = Math.floor((deadline - Date.now()) / 1000);
			if (remaining < 5)
				throw new Error(
					"El tiempo se agotó durante la conexión SSH; no se inició la herramienta.",
				);
			payload = {
				...payload,
				query: {
					...query,
					timeoutSeconds: Math.min(query.timeoutSeconds, remaining),
				},
			};
			if (plan) {
				const issues = analysisQueryIssues(
					validateAnalysisQuery(record(payload).query),
					plan,
				);
				if (issues.length) throw new Error(issues.join(" "));
			}
		}
		return await execJsonInput(
			connection,
			remoteProgram,
			payload,
			signal,
			6500000,
		);
	} finally {
		signal.removeEventListener("abort", abort);
		connection?.end();
		active = false;
	}
}
function record(value: unknown) {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error("Solicitud inválida.");
	return value as Record<string, unknown>;
}
export type ToolAvailability = {
	tool: string;
	available: boolean;
	detail: string;
	database: string;
};
export const inspectVulnerabilityTools = createServerFn({ method: "POST" })
	.validator((value: unknown) => kaliVerifications.require(value))
	.handler(async ({ data }): Promise<ToolAvailability[]> => {
		const rows = await remote(data, { operation: "inspect" }, 30);
		if (!Array.isArray(rows)) throw new Error("Diagnóstico inválido.");
		return rows.map((row) => {
			const r = record(row);
			return {
				tool: String(r.tool),
				available: r.available === true,
				detail: redactText(String(r.detail)).slice(0, 1500),
				database: redactText(String(r.database)).slice(0, 1500),
			};
		});
	});
export const runVulnerabilityAnalysis = createServerFn({ method: "POST" })
	.validator((value: unknown) => {
		const item = record(value);
		const query = validateAnalysisQuery(item.query);
		const access = kaliVerifications.requireTool(item, query.tool);
		const plan =
			item.plan === undefined ? undefined : validateScopePlan(item.plan);
		const issues = analysisQueryIssues(query, plan);
		if (issues.length) throw new Error(issues.join(" "));
		return { access, query, plan };
	})
	.handler(async ({ data }) => {
		const result = record(
			await remote(
				data.access,
				{ operation: "run", query: data.query },
				data.query.timeoutSeconds,
				data.plan,
			),
		);
		if (typeof result.raw !== "string")
			throw new Error("Kali devolvió un reporte inválido.");
		const warnings = [
			"Una coincidencia no confirma aplicabilidad. Revisar versión, parches del proveedor y condiciones.",
			String(result.database ?? "Fecha de base desconocida."),
		];
		if (result.pinnedAddress)
			warnings.push(
				`Conexión fijada a ${String(result.pinnedAddress)} desde Kali. El dominio de la URL se conserva en Host y SNI; no se siguen redirecciones.`,
			);
		const diagnostic = redactText(
			[
				["nikto", "testssl"].includes(data.query.tool)
					? String(result.stdout ?? "")
					: "",
				String(result.stderr ?? ""),
			]
				.filter(Boolean)
				.join("\n"),
		).slice(-8000);
		for (let offset = 0; offset < diagnostic.length; offset += 1800)
			warnings.push(
				`Diagnóstico de la herramienta (${Math.floor(offset / 1800) + 1}): ${diagnostic.slice(offset, offset + 1800)}`,
			);
		let error = redactText(String(result.error ?? ""));
		if (result.code !== 0)
			error ||= redactText(
				`La herramienta terminó con código ${result.code ?? "desconocido"}. ${String(result.stderr ?? "").slice(0, 2000)}`,
			);
		let findings: ReturnType<typeof parseAnalysisReport> = [];
		try {
			if (result.reportAvailable === false)
				throw new Error("La herramienta no generó un reporte JSON legible.");
			findings = parseAnalysisReport(data.query.tool, result.raw);
		} catch (e) {
			error ||= e instanceof Error ? e.message : "Reporte no reconocido.";
			warnings.push(
				"Se conserva la salida para revisión manual; no se interpreta como cero vulnerabilidades.",
			);
		}
		if (result.raw.length > 50000)
			warnings.push(
				"Evidencia visible recortada a 50.000 caracteres; exporta también el reporte completo antes de cerrar esta página.",
			);
		const raw = redactText(result.raw);
		const evidence: AnalysisEvidence = {
			id: crypto.randomUUID(),
			tool: data.query.tool,
			target:
				data.query.target ||
				(data.query.tool === "trivy"
					? data.query.path
					: `${data.query.product} ${data.query.version}`.trim() ||
						data.query.cve ||
						data.query.cpe ||
						"Consulta CVE"),
			port:
				["nikto", "testssl"].includes(data.query.tool) || data.query.target
					? data.query.port
					: undefined,
			query: analysisCommand(data.query),
			date: new Date().toISOString(),
			raw: raw.slice(0, 50000),
			warnings,
			error: error.slice(0, 4000),
			scopeRevision: data.plan?.revision,
			executor: executorIdentity(data.access.ssh),
		};
		return {
			evidence,
			findings,
			fullReport: raw,
			reportFormat:
				result.reportAvailable === false ? ("txt" as const) : ("json" as const),
			stderr: diagnostic,
		};
	});
