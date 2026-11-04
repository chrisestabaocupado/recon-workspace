import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import { createServerFn } from "@tanstack/react-start";
import type { Client } from "ssh2";
import type { RunnerEvent } from "../lib/execution.ts";
import {
	executorIdentity,
	type KaliAccess,
	type SshSettings,
	validateKaliDiagnostic,
	validateKaliTools,
	validateSsh,
} from "../lib/kali.ts";
import { validateNmapArgs } from "../lib/nmap-command.ts";
import {
	addressRange,
	pinResolvedScope,
	type ScopePlan,
	scopedCommandIssues,
} from "../lib/scope.ts";
import { JobManager, type Launch, type Transport } from "./job-manager.ts";
import { kaliVerifications } from "./kali-access.ts";
import diagnosticSource from "./kali-diagnostic.mjs?raw";
import { validateStartInput } from "./nmap-input.ts";
import runnerSource from "./runner.mjs?raw";
import { connectSsh, execJsonInput, execText } from "./ssh.ts";
export type StartJobInput = KaliAccess & {
	args: string[];
	projectId: string;
	authorized: boolean;
	timeoutSeconds: number;
	plan?: ScopePlan;
};
const manager = new JobManager();

function installRemoteRunner(connection: Client, signal: AbortSignal) {
	signal.throwIfAborted();
	return new Promise<void>((resolve, reject) => {
		let settled = false;
		let remoteSftp: import("ssh2").SFTPWrapper | undefined;
		const disconnected = () =>
			done(new Error("Se perdió SSH al preparar el runner de Kali."));
		const aborted = () =>
			done(new Error("Se agotó el tiempo para preparar el runner de Kali."));
		const done = (failure?: Error | null) => {
			if (settled) return;
			settled = true;
			signal.removeEventListener("abort", aborted);
			connection.removeListener("close", disconnected);
			remoteSftp?.end();
			if (failure) reject(failure);
			else resolve();
		};
		signal.addEventListener("abort", aborted, { once: true });
		connection.once("close", disconnected);
		connection.sftp((error, sftp) => {
			if (error) {
				done(error);
				return;
			}
			remoteSftp = sftp;
			if (settled || signal.aborted) {
				sftp.end();
				aborted();
				return;
			}
			sftp.realpath(".", (homeError, home) => {
				if (homeError || !home) {
					done(homeError ?? new Error("No pude resolver el home remoto."));
					return;
				}
				const directory = path.posix.join(home, ".recon-workspace");
				const upload = () => {
					const file = sftp.createWriteStream(
						path.posix.join(directory, "runner.mjs"),
						{ mode: 0o600 },
					);
					file.once("error", done);
					file.once("close", () => done());
					file.end(runnerSource);
				};
				sftp.stat(directory, (statError) => {
					if (!statError) {
						upload();
						return;
					}
					sftp.mkdir(directory, { mode: 0o700 }, (mkdirError) => {
						if (mkdirError) done(mkdirError);
						else upload();
					});
				});
			});
		});
	});
}
function decoder(
	onEvent: (event: RunnerEvent) => void,
	onFailure: (message: string) => void,
) {
	let pending = "";
	const utf8 = new StringDecoder("utf8");
	return (data: Buffer | string) => {
		pending += typeof data === "string" ? data : utf8.write(data);
		if (pending.length > 32 * 1024 * 1024) {
			pending = "";
			onFailure("El runner emitió un mensaje demasiado extenso.");
			return;
		}
		const lines = pending.split("\n");
		pending = lines.pop() ?? "";
		for (const line of lines) {
			if (!line.trim()) continue;
			try {
				const event = JSON.parse(line) as RunnerEvent;
				if (
					event.type === "log" &&
					(typeof event.data !== "string" ||
						!["stdout", "stderr"].includes(event.stream))
				)
					throw new Error("Log inválido");
				if (
					(event.type === "error" || event.type === "warning") &&
					typeof event.message !== "string"
				)
					throw new Error("Error inválido");
				if (event.type === "artifact" && typeof event.data !== "string")
					throw new Error("Artefacto inválido");
				if (
					!["ready", "log", "error", "warning", "artifact", "exit"].includes(
						event.type,
					)
				)
					throw new Error("Evento inválido");
				onEvent(event);
			} catch {
				onFailure("El runner emitió datos de control inválidos.");
			}
		}
	};
}
function launchRemote(settings: SshSettings): Launch {
	return async (signal, onEvent, onClose) => {
		const connection = await connectSsh(settings, signal);
		const abort = () => connection.end();
		signal.addEventListener("abort", abort, { once: true });
		connection.on("error", (error) => onClose(error.message));
		connection.once("close", () => {
			signal.removeEventListener("abort", abort);
			onClose(
				"Se perdió SSH sin confirmar la salida. El runner intentará detener Nmap al cerrar su entrada.",
			);
		});
		try {
			signal.throwIfAborted();
			await installRemoteRunner(connection, signal);
			signal.throwIfAborted();
			return await new Promise<Transport>((resolve, reject) => {
				connection.exec(
					"exec node ~/.recon-workspace/runner.mjs",
					(error, stream) => {
						if (error) {
							reject(error);
							return;
						}
						stream.on("data", decoder(onEvent, onClose));
						stream.stderr.on("data", (data: Buffer) =>
							onEvent({ type: "log", stream: "stderr", data: data.toString() }),
						);
						stream.once("error", (streamError: Error) =>
							onClose(streamError.message),
						);
						stream.once("close", () => {
							onClose();
							connection.end();
						});
						resolve({
							send: (message) => {
								if (stream.destroyed)
									throw new Error("El canal SSH ya está cerrado.");
								stream.write(`${JSON.stringify(message)}\n`);
							},
							close: () => {
								stream.end();
								connection.end();
							},
						});
					},
				);
			});
		} catch (error) {
			connection.end();
			throw error;
		}
	};
}
export const verifySsh = createServerFn({ method: "POST" })
	.validator((value: unknown) => {
		if (!value || typeof value !== "object") throw new Error("Configura SSH.");
		const settings = value as SshSettings;
		validateSsh({
			...settings,
			fingerprint: settings.fingerprint || "SHA256:unverified",
		});
		return settings;
	})
	.handler(async ({ data }) => {
		const signal = AbortSignal.timeout(30000);
		let connection: Client | undefined;
		try {
			connection = await connectSsh(data, signal);
			const connected = connection;
			signal.addEventListener("abort", () => connected.end(), { once: true });
			const diagnostic = await execJsonInput(
				connection,
				diagnosticSource,
				{},
				signal,
				30000,
			);
			const version = validateKaliDiagnostic(diagnostic);
			const tools = validateKaliTools(
				(diagnostic as { tools?: unknown }).tools,
			);
			await installRemoteRunner(connection, signal);
			await execText(
				connection,
				"node --check ~/.recon-workspace/runner.mjs",
				signal,
			);
			return {
				connected: true as const,
				version: `${version} · Runner preparado`,
				...kaliVerifications.issue(data, Date.now(), tools),
				fingerprint: data.fingerprint,
			};
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "Falló el diagnóstico SSH.";
			return {
				connected: false as const,
				fingerprint: message.match(/SHA256:[A-Za-z0-9+/]+/)?.[0],
				error: message,
			};
		} finally {
			connection?.end();
		}
	});
export const startNmapJob = createServerFn({ method: "POST" })
	.validator(validateStartInput)
	.handler(async ({ data }) => {
		const args = await pinDnsTargets(data);
		const issues = scopedCommandIssues(
			data.args,
			data.plan,
			data.timeoutSeconds,
		);
		if (issues.length) throw new Error(issues.join("\n"));
		const launch = launchRemote(data.ssh);
		const deadline = Date.now() + data.timeoutSeconds * 1000;
		const result = manager.start(
			{
				projectId: data.projectId,
				args,
				mode: data.mode,
				timeoutMs: data.timeoutSeconds * 1000,
			},
			async (signal, onEvent, onClose) => {
				const transport = await launch(signal, onEvent, onClose);
				if (
					Date.now() >= deadline ||
					(data.plan && Date.now() >= Date.parse(data.plan.windowEnd))
				) {
					transport.close();
					throw new Error(
						"El inicio superó la ventana o duración autorizada. No se inició Nmap.",
					);
				}
				return transport;
			},
		);
		return {
			...result,
			scopeRevision: data.plan?.revision,
			executor: executorIdentity(data.ssh),
		};
	});

// Resolve on the executor, then pin numeric targets so Nmap cannot resolve a
// different address between scope validation and launch. No raw shell input.
async function pinDnsTargets(input: StartJobInput): Promise<string[]> {
	const config = validateNmapArgs(input.args);
	const names = [
		...new Set(
			[...config.targets, ...(input.plan?.excludes ?? [])].filter(
				(target) => !addressRange(target),
			),
		),
	];
	if (!names.length || !input.plan || !config.targets.length) return input.args;
	if (names.length > 64)
		throw new Error(
			"La comprobación admite hasta 64 nombres DNS entre objetivos y exclusiones. Divide el plan o usa exclusiones IP/CIDR verificadas.",
		);
	const family = config.values.ipv6 ? 6 : 4;
	let resolved: Record<string, string[]>;
	const signal = AbortSignal.timeout(15000);
	const connection = await connectSsh(input.ssh, signal);
	const abort = () => connection.end();
	signal.addEventListener("abort", abort, { once: true });
	try {
		const resolver =
			'const {lookup}=await import("node:dns/promises");let text="";for await(const chunk of process.stdin)text+=chunk;const {names,family}=JSON.parse(text);const pairs=await Promise.all(names.map(async name=>[name,(await lookup(name,{all:true,family})).map(r=>r.address)]));console.log(JSON.stringify(Object.fromEntries(pairs)))';
		resolved = (await execJsonInput(
			connection,
			resolver,
			{ names, family },
			signal,
			100000,
		)) as Record<string, string[]>;
	} finally {
		signal.removeEventListener("abort", abort);
		connection.end();
	}
	return pinResolvedScope(
		input.args,
		input.plan,
		resolved,
		input.timeoutSeconds,
	);
}
function validateJobQuery(value: unknown) {
	if (!value || typeof value !== "object")
		throw new Error("Ejecución inválida.");
	const query = value as { id?: string; offset?: number };
	if (typeof query.id !== "string" || !/^[a-f\d-]{36}$/i.test(query.id))
		throw new Error("ID de ejecución inválido.");
	if (
		query.offset !== undefined &&
		(!Number.isSafeInteger(query.offset) || query.offset < 0)
	)
		throw new Error("Offset inválido.");
	return { id: query.id, offset: query.offset ?? 0 };
}
export const getNmapJob = createServerFn({ method: "GET" })
	.validator(validateJobQuery)
	.handler(async ({ data }) => manager.get(data.id, data.offset));
export const cancelNmapJob = createServerFn({ method: "POST" })
	.validator(validateJobQuery)
	.handler(async ({ data }) => manager.cancel(data.id));
export const getNmapArtifact = createServerFn({ method: "GET" })
	.validator(validateJobQuery)
	.handler(async ({ data }) => manager.artifact(data.id));
