import { quoteArg, tokenizeCommand } from "./nmap-command.ts";
import { redactArgs, redactText, secretValues } from "./redaction.ts";
import type { WorkspaceData } from "./storage.ts";

export type OperationFailure = {
	id: string;
	phase: "recon" | "enumeration" | "analysis";
	stage: string;
	date: string;
	lastAt: string;
	occurrences: number;
	error: string;
	source?: string;
	target?: string;
	command?: string;
	scopeRevision?: number;
	jobId?: string;
};
export type FailureInput = Omit<
	OperationFailure,
	"id" | "date" | "lastAt" | "occurrences"
> & { id?: string; date?: string };
export const FAILURE_LIMIT = 300;
export type PendingOperation = OperationFailure & { projectId: string | null };
export function validatePendingOperations(value: unknown): PendingOperation[] {
	if (value === undefined) return [];
	if (!Array.isArray(value) || value.length > 20)
		throw new Error("Operaciones pendientes inválidas.");
	const validated = validateFailures(value);
	return validated.map((f, index) => {
		const id = value[index].projectId;
		if (id !== null && (typeof id !== "string" || !id || id.length > 128))
			throw new Error("Proyecto de operación pendiente inválido.");
		return { ...f, projectId: id };
	});
}
export function recoverPendingOperations(
	workspace: WorkspaceData,
): WorkspaceData {
	let next = workspace;
	for (const pending of workspace.pendingOperations ?? []) {
		next = appendFailure(next, pending.projectId, {
			...pending,
			lastAt: new Date().toISOString(),
			stage: `${pending.stage} · resultado sin confirmar`,
			error:
				"La página se cerró o recargó antes de guardar la respuesta. El resultado no está confirmado; este registro no implica que la operación fallara en Kali.",
		});
	}
	return { ...next, pendingOperations: [] };
}
function safe(value: string) {
	return redactText(
		value.replace(
			/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g,
			"[CLAVE PRIVADA REDACTADA]",
		),
	).slice(0, 4000);
}
export function validateFailures(value: unknown): OperationFailure[] {
	if (value === undefined) return [];
	if (!Array.isArray(value) || value.length > FAILURE_LIMIT)
		throw new Error("Registro de incidencias inválido o demasiado extenso.");
	const result = value.map((raw): OperationFailure => {
		if (!raw || typeof raw !== "object")
			throw new Error("Incidencia inválida.");
		const text = (key: string, optional = false): string | undefined => {
			const v = raw[key];
			if (optional && v === undefined) return undefined;
			if (typeof v !== "string" || !v.trim() || v.length > 100000)
				throw new Error(`Incidencia: ${key} inválido.`);
			return safe(v);
		};
		if (
			raw.phase !== "recon" &&
			raw.phase !== "enumeration" &&
			raw.phase !== "analysis"
		)
			throw new Error("Fase de incidencia inválida.");
		const required = (key: string) => {
			const v = text(key);
			if (v === undefined) throw new Error("Incidencia incompleta.");
			return v;
		};
		const date = required("date");
		const lastAt = required("lastAt");
		if (
			!Number.isFinite(Date.parse(date)) ||
			!Number.isFinite(Date.parse(lastAt)) ||
			Date.parse(lastAt) < Date.parse(date)
		)
			throw new Error("Fecha de incidencia inválida.");
		if (!Number.isSafeInteger(raw.occurrences) || raw.occurrences < 1)
			throw new Error("Contador de incidencias inválido.");
		const command = text("command", true);
		let secrets: string[] = [];
		try {
			if (command) {
				const args = tokenizeCommand(raw.command);
				secrets = secretValues(args);
				for (let i = 0; i < args.length; i++) {
					const scriptArgs =
						args[i] === "--script-args"
							? args[i + 1]
							: args[i].startsWith("--script-args=")
								? args[i].slice(14)
								: undefined;
					if (scriptArgs)
						for (const match of scriptArgs.matchAll(
							/=\s*("[^"]*"|'[^']*'|[^,{}\s]+)/g,
						))
							secrets.push(match[1].replace(/^["']|["']$/g, ""));
				}
			}
		} catch {
			/* Invalid imported commands are redacted below. */
		}
		let sanitizedCommand = command;
		if (command) {
			try {
				sanitizedCommand = redactArgs(tokenizeCommand(command))
					.map(quoteArg)
					.join(" ");
			} catch {
				sanitizedCommand = command.replace(
					/--script-args(?:=|\s+).*/s,
					"--script-args [REDACTADO]",
				);
			}
		}
		return {
			id: required("id"),
			phase: raw.phase,
			stage: required("stage"),
			date,
			lastAt,
			occurrences: raw.occurrences,
			error: redactText(required("error"), secrets),
			source: text("source", true),
			target: text("target", true),
			command: sanitizedCommand,
			jobId: text("jobId", true),
			scopeRevision:
				Number.isSafeInteger(raw.scopeRevision) && raw.scopeRevision > 0
					? raw.scopeRevision
					: undefined,
		};
	});
	if (new Set(result.map((f) => f.id)).size !== result.length)
		throw new Error("IDs de incidencias duplicados.");
	return result;
}
export function makeFailure(input: FailureInput): OperationFailure {
	const date = input.date ?? new Date().toISOString();
	return validateFailures([
		{
			...input,
			stage: safe(input.stage),
			target: input.target ? safe(input.target) : undefined,
			source: input.source ? safe(input.source) : undefined,
			error: safe(input.error || "Error sin detalle."),
			id: input.id ?? crypto.randomUUID(),
			date,
			lastAt: date,
			occurrences: 1,
		},
	])[0];
}
export function appendFailure(
	workspace: WorkspaceData,
	projectId: string | null,
	failure: OperationFailure,
): WorkspaceData {
	const add = (items: OperationFailure[] = []) => {
		const existing = items.find((f) => f.id === failure.id);
		// A stable ID groups repeated polling errors, never separate operator attempts.
		return existing
			? items.map((f) =>
					f.id === failure.id
						? {
								...f,
								error: failure.error,
								lastAt:
									Date.parse(f.lastAt) >= Date.parse(failure.lastAt)
										? f.lastAt
										: failure.lastAt,
								occurrences: f.occurrences + 1,
							}
						: f,
				)
			: [failure, ...items].slice(0, FAILURE_LIMIT);
	};
	if (!projectId || !workspace.projects.some((p) => p.id === projectId))
		return { ...workspace, failures: add(workspace.failures) };
	return {
		...workspace,
		projects: workspace.projects.map((p) =>
			p.id === projectId ? { ...p, failures: add(p.failures) } : p,
		),
	};
}
export function failuresMarkdown(failures: OperationFailure[]): string {
	const literal = (s: string) => s.replace(/[\\`*_{}[\]<>#|]/g, "\\$&");
	return [
		"## Incidencias e intentos fallidos",
		"",
		"Un fallo de consulta no demuestra que el activo o el registro no exista. Estos registros no son evidencias de vulnerabilidades.",
		"",
		...failures.flatMap((f) => [
			`### ${literal(f.stage)} · ${f.phase === "recon" ? "Reconocimiento" : f.phase === "analysis" ? "Análisis" : "Enumeración"}`,
			`ID: ${literal(f.id)}; fecha: ${f.date}; última aparición: ${f.lastAt}; apariciones: ${f.occurrences}`,
			`Plan: ${f.scopeRevision ? `r${f.scopeRevision}` : "sin revisión registrada"}`,
			...(f.source ? [`Fuente: ${literal(f.source)}`] : []),
			...(f.target ? [`Objetivo: ${literal(f.target)}`] : []),
			...(f.jobId ? [`Ejecución: ${literal(f.jobId)}`] : []),
			...(f.command ? [`Comando: ${literal(f.command)}`] : []),
			`Error: ${literal(f.error)}`,
			"",
		]),
		...(failures.length ? [] : ["Sin incidencias registradas."]),
	].join("\n");
}
