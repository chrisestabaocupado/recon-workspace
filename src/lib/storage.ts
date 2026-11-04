import type { ExecutionSnapshot, JobState } from "./execution.ts";
import { type KaliExecutor, validateExecutor } from "./kali.ts";
import { quoteArg, tokenizeCommand } from "./nmap-command.ts";
import {
	type OperationFailure,
	type PendingOperation,
	validateFailures,
	validatePendingOperations,
} from "./operation-history.ts";
import { type ReconData, validateReconData } from "./recon.ts";
import { redactArgs, redactText } from "./redaction.ts";
import type { ObservedHost } from "./results.ts";
import { type ScopePlan, validateScopePlan } from "./scope.ts";
import {
	type CheckAttempt,
	evidenceCheck,
	mergeCheckHistory,
	runCheck,
	validateCheckHistory,
} from "./test-checklist.ts";

// Keep the original keys so existing browser data remains available after renaming.
export const STORAGE_KEY = "one-two-three:workspace:v1";
export const SSH_KEY = "one-two-three:ssh:v1";
export const ACTIVE_JOB_KEY = "one-two-three:active-job:v1";
const MAX_IMPORT = 5 * 1024 * 1024;
export type SavedSshSettings = {
	host: string;
	port: number;
	username: string;
	privateKeyPath: string;
	fingerprint: string;
};
export type WorkspaceTarget = { id: string; value: string; note: string };
export type RunSummary = {
	id: string;
	command: string;
	state: JobState;
	date: string;
	excerpt: string;
	hosts?: ObservedHost[];
	mode?: "local" | "ssh";
	targets?: string[];
	truncated?: boolean;
	error?: string;
	reportError?: string;
	scopeRevision?: number;
	executor?: KaliExecutor;
};
export type WorkspaceProject = {
	id: string;
	name: string;
	scope: string;
	createdAt: string;
	targets: WorkspaceTarget[];
	executions: number;
	lastRuns?: RunSummary[];
	failures?: OperationFailure[];
	checkHistory?: CheckAttempt[];
	plan?: ScopePlan;
	planHistory?: ScopePlan[];
	recon?: ReconData;
};
export type WorkspaceData = {
	pendingOperations?: PendingOperation[];
	projects: WorkspaceProject[];
	failures?: OperationFailure[];
	selectedProjectId: string | null;
};
export const emptyWorkspace = (): WorkspaceData => ({
	projects: [],
	selectedProjectId: null,
});
export const defaultSshSettings = (): SavedSshSettings => ({
	host: "",
	port: 22,
	username: "",
	privateKeyPath: "",
	fingerprint: "",
});

function record(value: unknown, label: string): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error(`${label}: estructura inválida.`);
	return value as Record<string, unknown>;
}
function str(value: unknown, label: string, max = 8192, empty = false): string {
	if (
		typeof value !== "string" ||
		value.length > max ||
		(!empty && !value.trim())
	)
		throw new Error(`${label}: texto inválido.`);
	return redactText(value);
}
function date(value: unknown, label: string): string {
	const result = str(value, label, 100);
	if (!Number.isFinite(Date.parse(result)))
		throw new Error(`${label}: fecha inválida.`);
	return result;
}
function array(value: unknown, label: string, max: number): unknown[] {
	if (!Array.isArray(value) || value.length > max)
		throw new Error(`${label}: lista inválida o demasiado extensa.`);
	return value;
}
export function redactCommand(command: string): string {
	try {
		return redactArgs(tokenizeCommand(command)).map(quoteArg).join(" ");
	} catch {
		return redactText(command).replace(
			/--script-args(?:=|\s+).*/s,
			"--script-args [REDACTADO]",
		);
	}
}
function hosts(value: unknown): ObservedHost[] {
	return array(value, "Hosts", 5000).map((item) => {
		const host = record(item, "Host");
		return {
			address: str(host.address, "Dirección", 255),
			hostname:
				host.hostname === undefined
					? undefined
					: str(host.hostname, "Hostname", 255, true),
			status:
				host.status === undefined
					? undefined
					: str(host.status, "Estado de host", 100),
			ports: array(host.ports, "Puertos", 65536).map((entry) => {
				const port = record(entry, "Puerto");
				if (
					!Number.isInteger(port.port) ||
					Number(port.port) < 0 ||
					Number(port.port) > 65535
				)
					throw new Error("Puerto fuera de rango.");
				return {
					port: Number(port.port),
					protocol: str(port.protocol, "Protocolo", 20),
					state: str(port.state, "Estado de puerto", 100),
					service: str(port.service, "Servicio", 255),
					product:
						port.product === undefined
							? undefined
							: str(port.product, "Producto", 4096, true),
					cpes:
						port.cpes === undefined
							? undefined
							: array(port.cpes, "CPE", 50).map((v) =>
									str(v, "CPE", 1000, true),
								),
					version:
						port.version === undefined
							? undefined
							: str(port.version, "Versión", 4096, true),
				};
			}),
		};
	});
}
const states: JobState[] = [
	"starting",
	"running",
	"cancelling",
	"completed",
	"failed",
	"cancelled",
	"timed_out",
	"unknown",
	"interrupted",
];
function run(value: unknown): RunSummary {
	const item = record(value, "Ejecución");
	if (!states.includes(item.state as JobState))
		throw new Error("Estado de ejecución inválido.");
	if (item.mode !== undefined && item.mode !== "local" && item.mode !== "ssh")
		throw new Error("Modo de ejecución inválido.");
	return {
		id: str(item.id, "ID de ejecución", 128),
		executor:
			item.executor === undefined ? undefined : validateExecutor(item.executor),
		scopeRevision:
			Number.isSafeInteger(item.scopeRevision) && Number(item.scopeRevision) > 0
				? Number(item.scopeRevision)
				: undefined,
		command: redactCommand(str(item.command, "Comando", 100000)),
		state: item.state as JobState,
		date: date(item.date, "Fecha de ejecución"),
		excerpt: redactText(str(item.excerpt, "Extracto", 100000, true)).slice(
			-7000,
		),
		hosts: item.hosts === undefined ? undefined : hosts(item.hosts),
		mode: item.mode as RunSummary["mode"],
		targets:
			item.targets === undefined
				? undefined
				: array(item.targets, "Objetivos de ejecución", 10000).map((target) =>
						str(target, "Objetivo"),
					),
		truncated: item.truncated === true,
		error:
			item.error === undefined
				? undefined
				: str(item.error, "Error", 8192, true),
		reportError:
			item.reportError === undefined
				? undefined
				: str(item.reportError, "Error de reporte", 8192, true),
	};
}
export function validateWorkspace(value: unknown): WorkspaceData {
	const item = record(value, "Workspace");
	const projects = array(item.projects, "Proyectos", 200).map((entry) => {
		const project = record(entry, "Proyecto");
		if (
			!Number.isSafeInteger(project.executions) ||
			Number(project.executions) < 0
		)
			throw new Error("Contador de ejecuciones inválido.");
		const targets = array(project.targets, "Objetivos", 10000).map((target) => {
			const data = record(target, "Objetivo");
			return {
				id: str(data.id, "ID de objetivo", 128),
				value: str(data.value, "Objetivo"),
				note: str(data.note, "Nota", 4096, true),
			};
		});
		if (new Set(targets.map((target) => target.id)).size !== targets.length)
			throw new Error("Hay IDs de objetivos duplicados.");
		return {
			id: str(project.id, "ID de proyecto", 128),
			failures: validateFailures(project.failures),
			checkHistory: validateCheckHistory(project.checkHistory),
			recon:
				project.recon === undefined
					? undefined
					: validateReconData(project.recon),
			plan:
				project.plan === undefined
					? undefined
					: validateScopePlan(project.plan),
			planHistory:
				project.planHistory === undefined
					? []
					: array(project.planHistory, "Revisiones del plan", 10).map(
							validateScopePlan,
						),
			name: str(project.name, "Nombre", 200),
			scope: str(project.scope, "Alcance", 8192, true),
			createdAt: date(project.createdAt, "Fecha del proyecto"),
			targets,
			executions: Number(project.executions),
			lastRuns:
				project.lastRuns === undefined
					? []
					: array(project.lastRuns, "Historial", 10).map(run),
		};
	});
	for (const project of projects)
		project.checkHistory = mergeCheckHistory(
			project.checkHistory,
			project.recon?.evidence.map(evidenceCheck),
			project.lastRuns.map(runCheck),
		);
	if (new Set(projects.map((project) => project.id)).size !== projects.length)
		throw new Error("Hay IDs de proyectos duplicados.");
	const selected = item.selectedProjectId;
	if (
		selected !== undefined &&
		selected !== null &&
		typeof selected !== "string"
	)
		throw new Error("ID de proyecto seleccionado inválido.");
	return {
		projects,
		failures: validateFailures(item.failures),
		pendingOperations: validatePendingOperations(item.pendingOperations),
		selectedProjectId: projects.some((project) => project.id === selected)
			? (selected as string)
			: (projects[0]?.id ?? null),
	};
}
export function readWorkspaceResult(): { data: WorkspaceData; error?: string } {
	try {
		const raw = window.localStorage.getItem(STORAGE_KEY);
		if (!raw) return { data: emptyWorkspace() };
		if (raw.length > MAX_IMPORT)
			throw new Error("El workspace excede el tamaño permitido.");
		return { data: validateWorkspace(JSON.parse(raw)) };
	} catch (error) {
		return {
			data: emptyWorkspace(),
			error: `No pude leer los proyectos guardados: ${error instanceof Error ? error.message : "datos inválidos"}. Exporta o revisa la copia existente antes de reemplazarla.`,
		};
	}
}
export function readWorkspace(): WorkspaceData {
	return readWorkspaceResult().data;
}
export function writeWorkspace(
	data: WorkspaceData,
): { ok: true } | { ok: false; message: string } {
	try {
		const content = JSON.stringify(validateWorkspace(data));
		if (content.length > MAX_IMPORT)
			throw new Error(
				"Los proyectos superan 5 MB. Exporta y limpia el historial antes de guardar.",
			);
		window.localStorage.setItem(STORAGE_KEY, content);
		return { ok: true };
	} catch (error) {
		return {
			ok: false,
			message:
				error instanceof DOMException && /Quota|QUOTA/.test(error.name)
					? "El navegador se quedó sin espacio. Exporta tus proyectos y limpia el historial."
					: error instanceof Error
						? error.message
						: "No se pudo guardar.",
		};
	}
}
export function exportWorkspace(data: WorkspaceData): string {
	return JSON.stringify(
		{
			format: "recon-workspace",
			version: 1,
			exportedAt: new Date().toISOString(),
			...validateWorkspace(data),
		},
		null,
		2,
	);
}
export function importWorkspace(text: string): WorkspaceData {
	if (text.length > MAX_IMPORT) throw new Error("La importación supera 5 MB.");
	const parsed = record(JSON.parse(text), "Importación");
	if (
		(parsed.format !== "recon-workspace" &&
			parsed.format !== "one-two-three-workspace") ||
		parsed.version !== 1
	)
		throw new Error("El archivo no es una exportación compatible.");
	return validateWorkspace(parsed);
}
export function readSshSettings(): SavedSshSettings {
	try {
		const raw = window.localStorage.getItem(SSH_KEY);
		const item = raw ? record(JSON.parse(raw), "SSH") : {};
		return {
			host: typeof item.host === "string" ? item.host : "",
			username: typeof item.username === "string" ? item.username : "",
			port:
				Number.isInteger(item.port) &&
				Number(item.port) > 0 &&
				Number(item.port) < 65536
					? Number(item.port)
					: 22,
			privateKeyPath:
				typeof item.privateKeyPath === "string" ? item.privateKeyPath : "",
			fingerprint: typeof item.fingerprint === "string" ? item.fingerprint : "",
		};
	} catch {
		return defaultSshSettings();
	}
}
export function writeSshSettings(settings: SavedSshSettings): boolean {
	try {
		const { host, port, username, privateKeyPath, fingerprint } = settings;
		window.localStorage.setItem(
			SSH_KEY,
			JSON.stringify({ host, port, username, privateKeyPath, fingerprint }),
		);
		return true;
	} catch {
		return false;
	}
}
export function readActiveExecution(): ExecutionSnapshot | null {
	try {
		const raw = window.localStorage.getItem(ACTIVE_JOB_KEY);
		if (!raw) return null;
		const item = record(JSON.parse(raw), "Ejecución activa");
		if (item.mode !== "local" && item.mode !== "ssh") return null;
		return {
			id: str(item.id, "ID", 128),
			executor:
				item.executor === undefined
					? undefined
					: validateExecutor(item.executor),
			projectId: str(item.projectId, "Proyecto", 128),
			command: redactCommand(str(item.command, "Comando", 100000)),
			targets: array(item.targets, "Objetivos", 10000).map((target) =>
				str(target, "Objetivo"),
			),
			mode: item.mode,
			startedAt: date(item.startedAt, "Inicio"),
			scopeRevision:
				Number.isSafeInteger(item.scopeRevision) &&
				Number(item.scopeRevision) > 0
					? Number(item.scopeRevision)
					: undefined,
		};
	} catch {
		return null;
	}
}
export function writeActiveExecution(value: ExecutionSnapshot | null): boolean {
	try {
		if (value) {
			const {
				id,
				projectId,
				command,
				targets,
				mode,
				startedAt,
				scopeRevision,
				executor,
			} = value;
			window.localStorage.setItem(
				ACTIVE_JOB_KEY,
				JSON.stringify({
					id,
					projectId,
					command: redactCommand(command),
					targets: targets.map((target) => redactText(target)),
					mode,
					startedAt,
					scopeRevision,
					executor: executor ? validateExecutor(executor) : undefined,
				}),
			);
		} else window.localStorage.removeItem(ACTIVE_JOB_KEY);
		return true;
	} catch {
		return false;
	}
}
