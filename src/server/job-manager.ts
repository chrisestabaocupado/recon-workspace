import { randomUUID } from "node:crypto";
import {
	isActiveJob,
	type JobState,
	type RunnerEvent,
} from "../lib/execution.ts";
import { quoteArg } from "../lib/nmap-command.ts";
import {
	redactArgs,
	redactText,
	StreamRedactor,
	secretValues,
} from "../lib/redaction.ts";

export type Transport = { send: (message: object) => void; close: () => void };
export type Launch = (
	signal: AbortSignal,
	onEvent: (event: RunnerEvent) => void,
	onClose: (error?: string) => void,
) => Promise<Transport>;
type Job = {
	id: string;
	projectId: string;
	command: string;
	mode: "local" | "ssh";
	state: JobState;
	logs: string;
	baseOffset: number;
	truncated: boolean;
	startedAt: string;
	finishedAt?: string;
	exitCode?: number | null;
	error?: string;
	artifact?: { text: string; filename: string };
	transport?: Transport;
	sentStart: boolean;
	cancellation?: "cancelled" | "timed_out";
	controller: AbortController;
	deadline?: ReturnType<typeof setTimeout>;
	cancelDeadline?: ReturnType<typeof setTimeout>;
	redactors: Record<"stdout" | "stderr", StreamRedactor>;
	secrets: string[];
};
export class JobManager {
	private jobs = new Map<string, Job>();
	private logLimit: number;
	private cancelGraceMs: number;
	constructor(logLimit = 1500000, cancelGraceMs = 8000) {
		this.logLimit = logLimit;
		this.cancelGraceMs = cancelGraceMs;
	}
	start(
		input: {
			projectId: string;
			args: string[];
			mode: "local" | "ssh";
			timeoutMs: number;
		},
		launch: Launch,
	) {
		if (
			[...this.jobs.values()].filter((job) => isActiveJob(job.state)).length >=
			4
		)
			throw new Error(
				"Ya hay cuatro ejecuciones activas. Espera o cancela una.",
			);
		const secrets = secretValues(input.args);
		const job: Job = {
			id: randomUUID(),
			projectId: input.projectId,
			command: ["nmap", ...redactArgs(input.args)].map(quoteArg).join(" "),
			mode: input.mode,
			state: "starting",
			logs: "",
			baseOffset: 0,
			truncated: false,
			startedAt: new Date().toISOString(),
			sentStart: false,
			controller: new AbortController(),
			secrets,
			redactors: {
				stdout: new StreamRedactor(secrets),
				stderr: new StreamRedactor(secrets),
			},
		};
		this.jobs.set(job.id, job);
		if (this.jobs.size > 20) {
			const old = [...this.jobs.values()].find(
				(entry) => !isActiveJob(entry.state) && entry.id !== job.id,
			);
			if (old) this.jobs.delete(old.id);
		}
		const args = [...input.args];
		job.deadline = setTimeout(
			() => this.requestCancel(job, "timed_out"),
			input.timeoutMs,
		);
		void (async () => {
			try {
				const transport = await launch(
					job.controller.signal,
					(event) => this.event(job, event),
					(error) => {
						if (isActiveJob(job.state))
							this.finish(
								job,
								job.sentStart ? "unknown" : (job.cancellation ?? "failed"),
								null,
								error ?? "El canal se cerró sin confirmar la salida de Nmap.",
							);
					},
				);
				job.transport = transport;
				if (!isActiveJob(job.state) || job.cancellation) {
					transport.close();
					if (isActiveJob(job.state))
						this.finish(job, job.cancellation ?? "failed", null);
					return;
				}
				job.sentStart = true;
				transport.send({
					type: "start",
					tool: "nmap",
					args,
					timeoutMs: input.timeoutMs,
				});
			} catch (error) {
				if (isActiveJob(job.state))
					this.finish(
						job,
						!job.sentStart && job.cancellation
							? job.cancellation
							: job.sentStart
								? "unknown"
								: "failed",
						null,
						error instanceof Error
							? error.message
							: "Falló el inicio de la ejecución.",
					);
			}
		})();
		return { id: job.id, startedAt: job.startedAt, command: job.command };
	}
	private append(job: Job, text: string) {
		job.logs += text;
		if (job.logs.length > this.logLimit) {
			const removed = job.logs.length - this.logLimit;
			job.logs = job.logs.slice(removed);
			job.baseOffset += removed;
			job.truncated = true;
		}
	}
	private event(job: Job, event: RunnerEvent) {
		if (!isActiveJob(job.state)) return;
		if (event.type === "ready" && job.state === "starting")
			job.state = "running";
		if (event.type === "log")
			this.append(job, job.redactors[event.stream].push(event.data));
		if (event.type === "error" || event.type === "warning") {
			job.error = redactText(event.message, job.secrets);
			this.append(job, `[${event.type}] ${job.error}\n`);
		}
		if (event.type === "artifact") {
			if (event.data.length <= 8 * 1024 * 1024)
				job.artifact = {
					text: redactText(event.data, job.secrets),
					filename: "nmap-report.xml",
				};
			else job.error = "El XML supera 8 MB y no está disponible para descarga.";
		}
		if (event.type === "exit")
			this.finish(
				job,
				event.reason ?? (event.code === 0 ? "completed" : "failed"),
				event.code,
				event.signal ? `Nmap terminó por señal ${event.signal}.` : undefined,
			);
	}
	private finish(
		job: Job,
		state: JobState,
		code?: number | null,
		error?: string,
	) {
		if (!isActiveJob(job.state)) return;
		this.append(
			job,
			job.redactors.stdout.flush() + job.redactors.stderr.flush(),
		);
		job.state = state;
		job.exitCode = code;
		job.error = error ? redactText(error, job.secrets) : job.error;
		job.finishedAt = new Date().toISOString();
		clearTimeout(job.deadline);
		clearTimeout(job.cancelDeadline);
		job.controller.abort();
		job.transport?.close();
		job.transport = undefined;
		job.secrets = [];
	}
	private requestCancel(job: Job, reason: "cancelled" | "timed_out") {
		if (!isActiveJob(job.state) || job.cancellation) return;
		job.cancellation = reason;
		job.state = "cancelling";
		if (!job.sentStart) {
			// Closing setup cannot launch Nmap: sending start is gated above.
			job.controller.abort();
		} else {
			try {
				job.transport?.send({ type: "cancel", reason });
			} catch {
				this.finish(
					job,
					"unknown",
					null,
					"No pude enviar la cancelación; no se confirmó la terminación remota.",
				);
				return;
			}
		}
		if (!isActiveJob(job.state)) return;
		job.cancelDeadline = setTimeout(
			() =>
				this.finish(
					job,
					job.sentStart ? "unknown" : reason,
					null,
					job.sentStart
						? "No se confirmó la terminación de Nmap. Revisa el proceso en el ejecutor."
						: undefined,
				),
			this.cancelGraceMs,
		);
	}
	cancel(id: string) {
		const job = this.jobs.get(id);
		if (!job) return { requested: false, state: "interrupted" as JobState };
		if (isActiveJob(job.state)) this.requestCancel(job, "cancelled");
		return { requested: isActiveJob(job.state), state: job.state };
	}
	get(id: string, requestedOffset = 0) {
		const job = this.jobs.get(id);
		if (!job) return { found: false as const };
		const offset = Math.max(
			job.baseOffset,
			Math.min(requestedOffset, job.baseOffset + job.logs.length),
		);
		return {
			found: true as const,
			id: job.id,
			projectId: job.projectId,
			command: job.command,
			mode: job.mode,
			state: job.state,
			logs: job.logs.slice(offset - job.baseOffset),
			offset: job.baseOffset + job.logs.length,
			gap: requestedOffset < job.baseOffset,
			truncated: job.truncated,
			startedAt: job.startedAt,
			finishedAt: job.finishedAt,
			exitCode: job.exitCode,
			error: job.error,
			artifactAvailable: Boolean(job.artifact),
		};
	}
	artifact(id: string) {
		return this.jobs.get(id)?.artifact ?? null;
	}
}
