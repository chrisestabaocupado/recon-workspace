import { hasNmapTargets, validateNmapArgs } from "../lib/nmap-command.ts";
import { scopedCommandIssues, validateScopePlan } from "../lib/scope.ts";
import type { StartJobInput } from "./jobs.ts";
import { kaliVerifications } from "./kali-access.ts";
export function validateStartInput(value: unknown): StartJobInput {
	if (!value || typeof value !== "object")
		throw new Error("Solicitud inválida.");
	const access = kaliVerifications.require(value);
	const input = value as Partial<StartJobInput>;
	if (!Array.isArray(input.args)) throw new Error("Argumentos inválidos.");
	const config = validateNmapArgs(input.args);
	if (!hasNmapTargets(config))
		throw new Error(
			"Agrega objetivos o un archivo de entrada; también puedes ejecutar una operación de diagnóstico de Nmap.",
		);
	if (
		typeof input.projectId !== "string" ||
		!input.projectId ||
		input.projectId.length > 128
	)
		throw new Error("Proyecto inválido.");
	if (input.authorized !== true)
		throw new Error(
			"Confirma que el objetivo está autorizado y dentro del alcance.",
		);
	if (
		!Number.isInteger(input.timeoutSeconds) ||
		Number(input.timeoutSeconds) < 5 ||
		Number(input.timeoutSeconds) > 86400
	)
		throw new Error(
			"El límite de ejecución debe estar entre 5 y 86400 segundos.",
		);
	const plan =
		input.plan === undefined ? undefined : validateScopePlan(input.plan);
	const scopeIssues = scopedCommandIssues(
		input.args,
		plan,
		Number(input.timeoutSeconds),
	);
	if (scopeIssues.length) throw new Error(scopeIssues.join("\n"));
	return {
		args: [...input.args],
		projectId: input.projectId,
		...access,
		authorized: true,
		timeoutSeconds: Number(input.timeoutSeconds),
		plan,
	};
}
