import type { ExecutionView } from "./execution.ts";
import { reconSources } from "./recon.ts";
import { redactText } from "./redaction.ts";
import type { ObservedHost, ObservedPort } from "./results.ts";
import { scopeTechniques, targetDecision } from "./scope.ts";
import {
	type RunSummary,
	redactCommand,
	type WorkspaceData,
	type WorkspaceProject,
} from "./storage.ts";
import {
	checkKinds,
	checkStatuses,
	projectChecklist,
} from "./test-checklist.ts";

export type ReportSection = {
	title: string;
	paragraphs?: string[];
	columns?: string[];
	rows?: string[][];
};
export type ProjectReport = {
	title: string;
	projectId: string;
	generatedAt: string;
	summary: {
		assets: number;
		hosts: number;
		openPorts: number;
		evidence: number;
	};
	sections: ReportSection[];
};
const runLabels: Record<RunSummary["state"], string> = {
	starting: "Iniciando",
	running: "En curso",
	cancelling: "Cancelando",
	completed: "Completada",
	failed: "Fallida",
	cancelled: "Cancelada",
	timed_out: "Tiempo agotado",
	unknown: "Sin confirmar",
	interrupted: "Interrumpida",
};
const planLabels = {
	draft: "Borrador",
	approved: "Aprobado",
	paused: "Pausado",
	closed: "Cerrado",
};
const assetLabels = {
	candidate: "Candidato",
	reviewed: "Revisado",
	discarded: "Descartado",
};
const revision = (value?: number) =>
	value ? `r${value}` : "Sin revisión registrada";
const executor = (run: Pick<RunSummary, "executor">) =>
	run.executor
		? `${run.executor.username}@${run.executor.host}:${run.executor.port} · ${run.executor.fingerprint}`
		: "Sin ejecutor registrado / importación manual";

type MappedHost = {
	host: ObservedHost;
	run: RunSummary;
	ports: { observed: ObservedPort; run: RunSummary }[];
};
// Retain the latest observation of each endpoint, not just the latest scan.
// Absence from another scan is not evidence that a previously seen port closed.
export function mappingInventory(project: WorkspaceProject): MappedHost[] {
	const hosts = new Map<string, MappedHost>();
	const runs = [...(project.lastRuns ?? [])]
		.reverse()
		.sort((a, b) => Date.parse(a.date) - Date.parse(b.date));
	for (const run of runs) {
		for (const host of run.hosts ?? []) {
			const key = host.address.trim().toLowerCase();
			const previous = hosts.get(key);
			const ports = new Map(
				(previous?.ports ?? []).map((port) => [
					`${port.observed.protocol.toLowerCase()}:${port.observed.port}`,
					port,
				]),
			);
			for (const observed of host.ports)
				ports.set(`${observed.protocol.toLowerCase()}:${observed.port}`, {
					observed,
					run,
				});
			hosts.set(key, {
				host: { ...host, hostname: host.hostname || previous?.host.hostname },
				run,
				ports: [...ports.values()].sort(
					(a, b) =>
						a.observed.port - b.observed.port ||
						a.observed.protocol.localeCompare(b.observed.protocol),
				),
			});
		}
	}
	return [...hosts.values()].sort((a, b) =>
		a.host.address.localeCompare(b.host.address, undefined, { numeric: true }),
	);
}

export function buildProjectReport(
	project: WorkspaceProject,
	generatedAt = new Date().toISOString(),
	live: {
		pending?: WorkspaceData["pendingOperations"];
		execution?: ExecutionView | null;
	} = {},
): ProjectReport {
	const inventory = mappingInventory(project);
	const assets = project.recon?.assets ?? [];
	const evidence = project.recon?.evidence ?? [];
	const runs = [...(project.lastRuns ?? [])].sort(
		(a, b) => Date.parse(b.date) - Date.parse(a.date),
	);
	const plan = project.plan;
	const scope = (value: string) =>
		plan ? targetDecision(value, plan).reason : "Sin plan definido";
	const summary = {
		assets: assets.filter((asset) => asset.status !== "discarded").length,
		hosts: inventory.length,
		openPorts: inventory.reduce(
			(total, host) =>
				total + host.ports.filter((p) => p.observed.state === "open").length,
			0,
		),
		evidence: evidence.length,
	};
	const sections: ReportSection[] = [
		{
			title: "Resumen",
			paragraphs: [
				`Proyecto: ${project.name}. Creado: ${project.createdAt}.`,
				project.scope || "Descripción del proyecto pendiente de definir.",
				`${summary.assets} activos no descartados, ${summary.hosts} hosts observados, ${summary.openPorts} puertos con último estado abierto y ${summary.evidence} evidencias de reconocimiento.`,
				"Este informe documenta reconocimiento y mapeo. No evalúa vulnerabilidades, severidad ni explotabilidad; no incluye explotación ni postexplotación.",
			],
		},
		{
			title: "Alcance y autorización",
			columns: ["Campo", "Valor"],
			rows: plan
				? [
						["Organización", plan.organization],
						["Objetivo", plan.objective],
						["Plan", `${revision(plan.revision)} · ${planLabels[plan.status]}`],
						[
							"Tipo",
							plan.assessmentType === "internal" ? "Interno" : "Externo",
						],
						["Responsable", plan.assessor],
						["Autoriza", plan.authorizer],
						["Referencia escrita", plan.authorizationReference],
						[
							"Registro de aprobación",
							plan.approvedAt || "Sin aprobación registrada",
						],
						["Activos incluidos", plan.includes.join("\n")],
						["Exclusiones", plan.excludes.join("\n") || "Ninguna registrada"],
						[
							"Ventana UTC",
							`${plan.windowStart || "Sin inicio"} → ${plan.windowEnd || "Sin fin"}`,
						],
						["Origen y conectividad", plan.sourceDescription],
						[
							"Técnicas permitidas",
							Object.entries(scopeTechniques)
								.filter(
									([key]) =>
										plan.techniques[key as keyof typeof scopeTechniques],
								)
								.map(([, label]) => label)
								.join(", "),
						],
						[
							"Fuentes públicas pasivas",
							plan.passiveRecon ? "Permitidas" : "No permitidas",
						],
						[
							"Límites",
							`Puertos: ${plan.allowedPorts}; hosts: ${plan.maxHosts}; paquetes/s: ${plan.maxRate}; duración máxima: ${plan.maxDurationSeconds}s`,
						],
						["Actividades prohibidas", plan.prohibitedActivities],
						["Criterios de parada", plan.stopConditions],
						["Tratamiento de datos", plan.dataHandling],
						[
							"Retención acordada",
							`${plan.retentionDays} días; borrado manual`,
						],
						["Entregables", plan.deliverables],
						["Notas", plan.notes],
					]
				: [
						[
							"Plan",
							"Sin plan registrado; este informe no constituye autorización para ejecutar consultas o escaneos.",
						],
					],
		},
		{
			title: "Objetivos registrados",
			columns: ["Objetivo", "Alcance actual", "Nota"],
			rows: project.targets.map((target) => [
				target.value,
				scope(target.value),
				target.note,
			]),
			paragraphs: project.targets.length ? [] : ["Sin objetivos registrados."],
		},
		{
			title: "Activos descubiertos",
			paragraphs: [
				"Un candidato o activo revisado no implica autorización ni disponibilidad actual. El alcance corresponde al plan actual; cada evidencia conserva su revisión de origen.",
				...(assets.length ? [] : ["Sin activos descubiertos guardados."]),
			],
			columns: [
				"Activo",
				"Revisión manual",
				"Alcance actual",
				"Evidencias",
				"Nota",
			],
			rows: assets.map((asset) => [
				asset.value,
				assetLabels[asset.status],
				scope(asset.value),
				asset.evidenceIds.join(", "),
				asset.note,
			]),
		},
		{
			title: "Mapa de hosts",
			paragraphs: [
				"Se combina la última observación guardada de cada host y puerto. Las observaciones pueden proceder de fechas y revisiones distintas; un puerto ausente en otro escaneo no se considera cerrado. No se infieren enlaces de red ni topología física.",
				...(inventory.length
					? []
					: ["Sin hosts observados en los reportes guardados."]),
			],
			columns: [
				"Dirección",
				"Nombre",
				"Estado observado",
				"Alcance actual",
				"Última observación",
			],
			rows: inventory.map(({ host, run }) => [
				host.address,
				host.hostname || "—",
				host.status || "Sin confirmar",
				scope(host.address),
				`${run.date}\n${revision(run.scopeRevision)} · ${run.id}`,
			]),
		},
		...inventory.map(
			({ host, ports }): ReportSection => ({
				title: `Puertos y servicios · ${host.address}`,
				paragraphs: ports.length
					? []
					: ["Sin puertos registrados para este host."],
				columns: [
					"Puerto",
					"Estado",
					"Servicio",
					"Producto / versión",
					"CPE",
					"Origen de la observación",
				],
				rows: ports.map(({ observed: p, run }) => [
					`${p.port}/${p.protocol}`,
					p.state,
					p.service,
					[p.product, p.version].filter(Boolean).join(" · ") ||
						"No identificado",
					p.cpes?.join("\n") || "—",
					`${run.date}\n${revision(run.scopeRevision)} · ${runLabels[run.state]}\nID: ${run.id}`,
				]),
			}),
		),
		{
			title: "Evidencias de reconocimiento",
			paragraphs: evidence.length
				? [
						"Las fuentes se presentan como referencias documentales; generar el informe no vuelve a consultarlas.",
					]
				: ["Sin evidencias guardadas."],
		},
		...evidence.map(
			(e): ReportSection => ({
				title: `Evidencia · ${e.id}`,
				paragraphs: [
					`${reconSources[e.source]} · ${e.query} · ${e.retrievedAt} · ${revision(e.scopeRevision)}`,
					`Fuente: ${e.sourceUrl || "Registro manual o consulta directa desde Kali"}`,
					`Ejecutor: ${executor(e)}`,
					`Activos vinculados: ${
						assets
							.filter((a) => a.evidenceIds.includes(e.id))
							.map((a) => a.value)
							.join(", ") || "Ninguno"
					}`,
					...e.warnings.map((warning) => `Advertencia: ${warning}`),
					...(e.issues ?? []).map(
						(issue) => `Incidencia: ${issue.stage} · ${issue.error}`,
					),
					...(e.notes ? [`Notas: ${e.notes}`] : []),
				],
				columns: ["Dato", "Valor"],
				rows: e.facts.map((fact) => [fact.label, fact.value]),
			}),
		),
		...(["recon", "enumeration"] as const).map(
			(phase): ReportSection => ({
				title: `Estado de recopilación · ${phase === "recon" ? "Reconocimiento" : "Mapeo"}`,
				paragraphs: [
					"Estado de la revisión actual. Pendiente significa sin ejecución registrada; no confirma ausencia de activos o servicios.",
				],
				columns: ["Actividad", "Objetivo", "Estado", "Último intento"],
				rows: projectChecklist(project, phase, {
					...live,
					includePrevious: false,
				}).map((row) => [
					checkKinds[row.kind],
					row.target,
					checkStatuses[row.status],
					row.attempts[0]
						? `${row.attempts[0].date}\n${row.attempts[0].detail}`
						: "Sin intento registrado",
				]),
			}),
		),
		{
			title: "Historial de ejecuciones",
			paragraphs: [
				`${project.executions} ejecuciones acumuladas; ${runs.length} reportes conservados en el historial local (máximo 10).`,
				"Los resultados fallidos, cancelados o con timeout pueden contener observaciones parciales. Los XML originales se descargan desde Enumeración mientras el servidor los conserve.",
			],
			columns: [
				"ID / fecha",
				"Resultado",
				"Revisión",
				"Objetivos",
				"Comando",
				"Ejecutor / incidencias",
			],
			rows: runs.map((run) => [
				`${run.id}\n${run.date}`,
				runLabels[run.state],
				revision(run.scopeRevision),
				run.targets?.join(", ") || "No registrados",
				redactCommand(run.command),
				[
					executor(run),
					run.error,
					run.reportError,
					run.truncated ? "Salida recortada" : "",
				]
					.filter(Boolean)
					.join("\n"),
			]),
		},
		{
			title: "Incidencias operativas del proyecto",
			paragraphs: [
				"Los fallos de consulta o ejecución no demuestran ausencia de activos. No se incluyen incidencias globales sin asociación a este proyecto.",
				...(project.failures?.length
					? []
					: ["Sin incidencias registradas en el proyecto."]),
			],
			columns: [
				"Fecha / fase",
				"Actividad / objetivo",
				"Detalle",
				"Trazabilidad",
			],
			rows: [...(project.failures ?? [])]
				.sort((a, b) => Date.parse(b.lastAt) - Date.parse(a.lastAt))
				.map((failure) => [
					`${failure.lastAt}\n${failure.phase === "recon" ? "Reconocimiento" : "Mapeo"}`,
					`${failure.stage}\n${failure.target || failure.source || "Sin objetivo"}`,
					failure.error,
					`${failure.id}\n${revision(failure.scopeRevision)} · ${failure.occurrences} apariciones${failure.jobId ? `\nEjecución: ${failure.jobId}` : ""}`,
				]),
		},
		{
			title: "Limitaciones y siguientes pasos",
			paragraphs: [
				"Instantánea de los datos disponibles en este navegador en la fecha de generación, no una comprobación en tiempo real. Solo se muestran hosts y servicios presentes en el historial conservado; el inventario no garantiza cobertura completa.",
				"El nombre de un servicio, su versión, un CPE o un certificado son datos observados, no hallazgos de vulnerabilidad ni conclusiones de seguridad.",
				"Revisar los candidatos y su pertenencia al alcance, contrastar las observaciones antiguas o parciales y completar la cobertura pendiente únicamente dentro del plan autorizado.",
				"Revisar los datos sensibles antes de compartir. Exportar el workspace para conservar una copia editable de los datos; este informe no sustituye el respaldo JSON ni los XML originales.",
			],
		},
	];
	const clean = (text: string) =>
		redactText(text).replace(
			/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g,
			"[CLAVE PRIVADA REDACTADA]",
		);
	return {
		title: clean(`Informe de reconocimiento y mapeo — ${project.name}`),
		projectId: clean(project.id),
		generatedAt,
		summary,
		sections: sections.map((section) => ({
			...section,
			title: clean(section.title),
			paragraphs: section.paragraphs?.map(clean),
			rows: section.rows?.map((row) => row.map((cell) => clean(cell || "—"))),
		})),
	};
}

export function reportMarkdown(report: ProjectReport): string {
	const literal = (text: string) =>
		text
			.replace(/&/g, "&amp;")
			.replace(/</g, "&lt;")
			.replace(/>/g, "&gt;")
			.replace(/[\\`*_{}[\]#|!]/g, "\\$&");
	const cell = (text: string) => literal(text).replace(/\r?\n/g, "<br>");
	return [
		`# ${cell(report.title)}`,
		"",
		`Proyecto: ${cell(report.projectId)}`,
		`Generado (UTC): ${cell(report.generatedAt)}`,
		"",
		...report.sections.flatMap((section) => [
			`## ${cell(section.title)}`,
			"",
			...(section.paragraphs ?? []).flatMap((paragraph) => [
				literal(paragraph),
				"",
			]),
			...(section.columns && section.rows?.length
				? [
						`| ${section.columns.map(cell).join(" | ")} |`,
						`| ${section.columns.map(() => "---").join(" | ")} |`,
						...section.rows.map((row) => `| ${row.map(cell).join(" | ")} |`),
						"",
					]
				: []),
		]),
	].join("\n");
}

export function reportFilename(projectId: string): string {
	return `informe-${projectId.replace(/[^a-z0-9_-]/gi, "-").slice(0, 100) || "proyecto"}.md`;
}
