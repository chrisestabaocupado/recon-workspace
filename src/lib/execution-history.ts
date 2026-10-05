import type { ExecutionSnapshot, JobState } from "./execution.ts";
import { appendFailure, makeFailure } from "./operation-history.ts";
import { redactText } from "./redaction.ts";
import { type ObservedHost, readNmapReport } from "./results.ts";
import { redactCommand, type WorkspaceData } from "./storage.ts";
import { appendCheckHistory, runCheck } from "./test-checklist.ts";
export function saveExecutionResult(
	workspace: WorkspaceData,
	snapshot: ExecutionSnapshot,
	result: {
		state: JobState;
		logs: string;
		xml?: string;
		date: string;
		truncated: boolean;
		error?: string;
	},
): WorkspaceData {
	let hosts: ObservedHost[] = [];
	let reportError: string | undefined;
	const report = result.xml || (result.truncated ? "" : result.logs);
	if (result.truncated && !result.xml)
		reportError =
			"No se creó inventario: el log es parcial y no hay XML completo. Importa el reporte del ejecutor.";
	else if (
		result.xml ||
		/<nmaprun|<\?xml|^Nmap scan report for |Nmap done:/m.test(report)
	) {
		try {
			hosts = readNmapReport(report);
		} catch (error) {
			reportError = `No se pudo interpretar el reporte: ${error instanceof Error ? error.message : "formato inválido"}`;
		}
	}
	let next = workspace;
	const fresh = !workspace.projects
		.find((p) => p.id === snapshot.projectId)
		?.lastRuns?.some((r) => r.id === snapshot.id);
	if (fresh) {
		for (const [stage, error] of [
			[
				"Ejecución Nmap",
				["failed", "timed_out", "unknown", "interrupted"].includes(result.state)
					? result.error || `Estado: ${result.state}`
					: undefined,
			],
			["Interpretar reporte", reportError],
		] as const) {
			if (error)
				next = appendFailure(
					next,
					snapshot.projectId,
					makeFailure({
						id: `${snapshot.id}:${stage}`,
						phase: "enumeration",
						stage,
						error,
						date: result.date,
						command: snapshot.command,
						target: snapshot.targets.join(", ") || undefined,
						scopeRevision: snapshot.scopeRevision,
						jobId: snapshot.id,
					}),
				);
		}
	}
	return {
		...next,
		projects: next.projects.map((project) => {
			if (
				project.id !== snapshot.projectId ||
				project.lastRuns?.some((run) => run.id === snapshot.id)
			)
				return project;
			const summary = {
				id: snapshot.id,
				command: redactCommand(snapshot.command),
				state: result.state,
				date: result.date,
				mode: snapshot.mode,
				executor: snapshot.executor,
				scopeRevision: snapshot.scopeRevision,
				targets: [...snapshot.targets],
				truncated: result.truncated,
				error: result.error ? redactText(result.error) : undefined,
				excerpt: redactText(result.logs).slice(-7000),
				hosts,
				reportError,
			};
			return {
				...project,
				executions: project.executions + 1,
				checkHistory: appendCheckHistory(
					project.checkHistory,
					runCheck(summary),
				),
				lastRuns: [summary, ...(project.lastRuns ?? [])].slice(0, 10),
			};
		}),
	};
}
