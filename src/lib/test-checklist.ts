import type { ExecutionView } from "./execution.ts";
import { parseNmapCommand } from "./nmap-command.ts";
import { makeFailure } from "./operation-history.ts";
import { type ReconEvidence, reconTarget } from "./recon.ts";
import { addressRange } from "./scope.ts";
import type { RunSummary, WorkspaceData, WorkspaceProject } from "./storage.ts";

export const checkKinds = {
	dns: "DNS",
	tls: "Certificado TLS del servicio",
	crtsh: "Certificados públicos · crt.sh",
	rdap: "Registro · RDAP",
	manual: "Evidencia manual",
	nmap: "Enumeración Nmap",
} as const;
export const checkStatuses = {
	provided: "Datos aportados",
	data: "Con datos",
	empty: "Sin datos",
	failed: "Falló",
	partial: "Parcial",
	unknown: "Sin confirmar",
	cancelled: "Cancelada",
	completed: "Ejecutada",
	running: "En curso",
	pending: "Pendiente",
} as const;
export type CheckAttempt = {
	id: string;
	phase: "recon" | "enumeration";
	kind: keyof typeof checkKinds;
	target: string;
	date: string;
	status: keyof typeof checkStatuses;
	detail: string;
	scopeRevision?: number;
	command?: string;
};
export const CHECK_HISTORY_LIMIT = 500;
export function validateCheckHistory(value: unknown): CheckAttempt[] {
	if (value === undefined) return [];
	if (!Array.isArray(value) || value.length > CHECK_HISTORY_LIMIT)
		throw new Error("Historial de pruebas inválido o demasiado extenso.");
	const checks = value.map((raw): CheckAttempt => {
		if (
			!raw ||
			typeof raw !== "object" ||
			!Object.hasOwn(checkKinds, raw.kind) ||
			!Object.hasOwn(checkStatuses, raw.status)
		)
			throw new Error("Prueba o resultado inválido.");
		if (
			(raw.kind === "nmap" ? "enumeration" : "recon") !== raw.phase ||
			typeof raw.target !== "string" ||
			!raw.target.trim() ||
			typeof raw.date !== "string" ||
			typeof raw.id !== "string" ||
			!raw.id ||
			typeof raw.detail !== "string"
		)
			throw new Error("Contexto de prueba inválido.");
		const sanitized = makeFailure({
			id: raw.id,
			phase: raw.phase,
			stage: raw.kind,
			date: raw.date,
			error: raw.detail || "Sin detalle.",
			target: raw.target,
			command: raw.command,
			scopeRevision: raw.scopeRevision,
		});
		return {
			id: sanitized.id,
			phase: raw.kind === "nmap" ? "enumeration" : "recon",
			kind: raw.kind,
			target: sanitized.target ?? "Sin objetivo",
			date: sanitized.date,
			status: raw.status,
			detail: sanitized.error,
			command: sanitized.command,
			scopeRevision: sanitized.scopeRevision,
		};
	});
	if (new Set(checks.map((c) => c.id)).size !== checks.length)
		throw new Error("IDs de pruebas duplicados.");
	return checks;
}
export function appendCheckHistory(
	history: CheckAttempt[] = [],
	attempt: CheckAttempt,
): CheckAttempt[] {
	return [attempt, ...history.filter((c) => c.id !== attempt.id)].slice(
		0,
		CHECK_HISTORY_LIMIT,
	);
}
export function mergeCheckHistory(
	...histories: (CheckAttempt[] | undefined)[]
): CheckAttempt[] {
	return [
		...new Map(
			histories.flatMap((h) => h ?? []).map((a) => [a.id, a]),
		).values(),
	]
		.sort((a, b) => Date.parse(b.date) - Date.parse(a.date))
		.slice(0, CHECK_HISTORY_LIMIT);
}
function commandTarget(command?: string): string {
	try {
		return (
			(command && parseNmapCommand(command).targets.join(", ")) ||
			"Objetivos del comando / diagnóstico"
		);
	} catch {
		return "Objetivos del comando / diagnóstico";
	}
}
export function evidenceCheck(e: ReconEvidence): CheckAttempt {
	const provided =
		e.source === "manual" ||
		e.warnings.some((w) => w.startsWith("JSON aportado por el operador:"));
	const partial =
		(e.source === "dns" &&
			e.facts.some((f) => f.value.startsWith("Consulta no disponible"))) ||
		(e.source === "tls" &&
			e.warnings.some(
				(w) =>
					w.startsWith("La cadena TLS no fue validada") ||
					/does not match|no coincide/i.test(w),
			));
	const hasData =
		e.source === "dns"
			? e.facts.some(
					(f) =>
						["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR"].includes(
							f.label,
						) &&
						f.value.trim() &&
						!/^(Sin registros|Consulta no disponible)/.test(f.value),
				)
			: e.source === "crtsh"
				? e.facts.some(
						(f) => f.label === "Certificados recibidos" && Number(f.value) > 0,
					)
				: true;
	let target = e.query;
	if (e.source === "tls") {
		try {
			const port = new URL(e.sourceUrl).port;
			if (port)
				target = `${target.includes(":") ? `[${target}]` : target}:${port}`;
		} catch {
			/* Legacy evidence may omit the URL. */
		}
	}
	return {
		id: `evidence:${e.id}`,
		phase: "recon",
		kind: e.source,
		target,
		date: e.retrievedAt,
		status: provided
			? "provided"
			: partial
				? "partial"
				: hasData
					? "data"
					: "empty",
		scopeRevision: e.scopeRevision,
		detail:
			[e.facts.map((f) => `${f.label}: ${f.value}`).join("; "), ...e.warnings]
				.join("\n")
				.slice(0, 4000) || "Observación registrada.",
	};
}
export function runCheck(run: RunSummary): CheckAttempt {
	const status: CheckAttempt["status"] =
		run.state === "completed"
			? run.reportError
				? "partial"
				: run.hosts?.length
					? "data"
					: /<nmaprun|Nmap done:/m.test(run.excerpt)
						? "empty"
						: "completed"
			: run.state === "cancelled"
				? "cancelled"
				: ["interrupted", "unknown"].includes(run.state)
					? "unknown"
					: ["starting", "running", "cancelling"].includes(run.state)
						? "running"
						: "failed";
	return {
		id: `run:${run.id}`,
		phase: "enumeration",
		kind: "nmap",
		target:
			run.targets?.join(", ") ||
			(run.command.includes("[reporte importado]")
				? "Reporte importado"
				: commandTarget(run.command)),
		date: run.date,
		status,
		command: run.command,
		scopeRevision: run.scopeRevision,
		detail:
			run.reportError ||
			run.error ||
			`${run.hosts?.length ?? 0} hosts registrados. ${status === "completed" ? "Operación completada; no hay un inventario de hosts para clasificar hallazgos." : ""}`,
	};
}
export type ChecklistRow = {
	key: string;
	kind: CheckAttempt["kind"];
	target: string;
	command?: string;
	status: CheckAttempt["status"];
	attempts: CheckAttempt[];
	recovered: boolean;
};
export function projectCheckAttempts(
	project: WorkspaceProject,
): CheckAttempt[] {
	const attempts = new Map<string, CheckAttempt>();
	for (const c of project.checkHistory ?? []) attempts.set(c.id, c);
	for (const e of project.recon?.evidence ?? [])
		attempts.set(`evidence:${e.id}`, evidenceCheck(e));
	for (const r of project.lastRuns ?? [])
		attempts.set(`run:${r.id}`, runCheck(r));
	for (const f of project.failures ?? []) {
		if (f.jobId && attempts.has(`run:${f.jobId}`)) continue;
		const reconQuery =
			f.phase === "recon" &&
			f.source &&
			Object.hasOwn(checkKinds, f.source) &&
			([
				"Consultar fuente",
				"Comprobar conexión y autorización",
				"Guardar evidencia",
			].includes(f.stage) ||
				f.stage.includes("resultado sin confirmar"));
		const nmap =
			f.phase === "enumeration" &&
			(["Iniciar Nmap", "Ejecución Nmap"].includes(f.stage) ||
				(f.stage.startsWith("Iniciar Nmap") &&
					f.stage.includes("resultado sin confirmar")));
		if (!reconQuery && !nmap) continue;
		attempts.set(`failure:${f.id}`, {
			id: `failure:${f.id}`,
			phase: nmap ? "enumeration" : "recon",
			kind: nmap ? "nmap" : (f.source as CheckAttempt["kind"]),
			target: f.target
				? f.source === "tls"
					? f.target.replace(/:443$/, "")
					: f.target
				: commandTarget(f.command),
			date: f.lastAt,
			status:
				f.stage.includes("sin confirmar") ||
				/Estado: (unknown|interrupted)/.test(f.error)
					? "unknown"
					: "failed",
			detail: f.error,
			scopeRevision: f.scopeRevision,
			command: f.command,
		});
	}
	return [...attempts.values()].sort(
		(a, b) => Date.parse(b.date) - Date.parse(a.date),
	);
}
export function projectChecklist(
	project: WorkspaceProject,
	phase: CheckAttempt["phase"],
	options: {
		includePrevious?: boolean;
		pending?: WorkspaceData["pendingOperations"];
		execution?: ExecutionView | null;
	} = {},
): ChecklistRow[] {
	const rows = new Map<string, ChecklistRow>();
	const key = (c: Pick<CheckAttempt, "kind" | "target" | "command">) =>
		JSON.stringify([
			c.kind,
			c.target.toLowerCase(),
			c.kind === "nmap" ? (c.command ?? "") : "",
		]);
	const revisionMatches = (c: Pick<CheckAttempt, "scopeRevision">) =>
		options.includePrevious ||
		(project.plan
			? c.scopeRevision === project.plan.revision
			: c.scopeRevision === undefined);
	const add = (c: CheckAttempt) => {
		if (c.phase !== phase || !revisionMatches(c)) return;
		const k = key(c);
		const existing = rows.get(k);
		if (existing) existing.attempts.push(c);
		else
			rows.set(k, {
				key: k,
				kind: c.kind,
				target: c.target,
				command: c.command,
				status: c.status,
				attempts: [c],
				recovered: false,
			});
	};
	for (const c of projectCheckAttempts(project)) add(c);
	for (const p of options.pending ?? [])
		if (p.projectId === project.id)
			add({
				id: `pending:${p.id}`,
				phase: p.phase,
				kind:
					p.phase === "enumeration"
						? "nmap"
						: (p.source as CheckAttempt["kind"]),
				target: p.target ?? commandTarget(p.command),
				date: p.date,
				status: "running",
				detail: "Esperando respuesta; el resultado todavía no está confirmado.",
				scopeRevision: p.scopeRevision,
				command: p.command,
			});
	const active = options.execution;
	if (
		active?.projectId === project.id &&
		["starting", "running", "cancelling"].includes(active.state)
	)
		add({
			id: `active:${active.id}`,
			phase: "enumeration",
			kind: "nmap",
			target:
				active.targets.join(", ") || "Objetivos del comando / diagnóstico",
			date: active.startedAt,
			status: "running",
			detail:
				active.state === "cancelling"
					? "Esperando confirmación de cancelación."
					: "Nmap está en curso.",
			scopeRevision: active.scopeRevision,
			command: active.command,
		});
	if (phase === "recon") {
		const targets = new Set(
			(project.plan?.includes ?? []).flatMap((target) => {
				try {
					return [reconTarget(target)];
				} catch {
					return [];
				}
			}),
		);
		for (const domain of targets)
			for (const kind of addressRange(domain)
				? (["dns", "tls"] as const)
				: (["dns", "tls", "crtsh", "rdap"] as const)) {
				const k = key({ kind, target: domain });
				if (!rows.has(k))
					rows.set(k, {
						key: k,
						kind,
						target: domain,
						status: "pending",
						attempts: [],
						recovered: false,
					});
			}
	} else if (!rows.size)
		rows.set("nmap:pending", {
			key: "nmap:pending",
			kind: "nmap",
			target:
				project.targets.map((t) => t.value).join(", ") ||
				"Objetivos por definir",
			status: "pending",
			attempts: [],
			recovered: false,
		});
	for (const row of rows.values()) {
		row.attempts.sort((a, b) => Date.parse(b.date) - Date.parse(a.date));
		row.status = row.attempts[0]?.status ?? "pending";
		row.recovered =
			["data", "empty", "completed"].includes(row.status) &&
			row.attempts.some((a) =>
				["failed", "unknown", "partial"].includes(a.status),
			);
	}
	return [...rows.values()];
}
export function checklistMarkdown(
	project: WorkspaceProject,
	phase: CheckAttempt["phase"],
	includePrevious = true,
	live: {
		pending?: WorkspaceData["pendingOperations"];
		execution?: ExecutionView | null;
	} = {},
): string {
	const literal = (s: string) => s.replace(/[\\`*_{}[\]<>#|]/g, "\\$&");
	return [
		"## Checklist de pruebas",
		"",
		"Con datos / sin datos describen el resultado de la recopilación, no la existencia o ausencia de vulnerabilidades. Pendiente significa sin ejecución registrada; consulta los permisos del plan antes de ejecutar.",
		"",
		...projectChecklist(project, phase, { includePrevious, ...live }).flatMap(
			(row) => [
				`- [${row.attempts.length ? "x" : " "}] ${checkKinds[row.kind]} · ${literal(row.target)} · **${checkStatuses[row.status]}**${row.recovered ? " · Reintento resuelto" : ""}`,
				...(row.command ? [`  Comando: ${literal(row.command)}`] : []),
				...row.attempts.map(
					(a) =>
						`  - ${a.date} · ${checkStatuses[a.status]} · ${a.scopeRevision ? `plan r${a.scopeRevision}` : "revisión no registrada"} · ${literal(a.detail)} · ID: ${literal(a.id)}`,
				),
				"",
			],
		),
	].join("\n");
}
