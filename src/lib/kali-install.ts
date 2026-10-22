import type { KaliToolCheck } from "./kali.ts";

export const installableTools = {
	dig: "bind9-dnsutils",
	openssl: "openssl",
} as const;
export type InstallableTool = keyof typeof installableTools;
export function missingInstallableTools(tools: KaliToolCheck[]) {
	return tools
		.filter(
			(t) => t.status === "missing" && Object.hasOwn(installableTools, t.tool),
		)
		.map((t) => t.tool as InstallableTool);
}
export function validateInstallTools(value: unknown): InstallableTool[] {
	if (
		!Array.isArray(value) ||
		!value.length ||
		value.length > Object.keys(installableTools).length ||
		new Set(value).size !== value.length ||
		value.some(
			(tool) =>
				typeof tool !== "string" || !Object.hasOwn(installableTools, tool),
		)
	)
		throw new Error(
			"Selecciona herramientas faltantes del catálogo de instalación.",
		);
	return [...value] as InstallableTool[];
}
export type KaliInstallView = {
	id: string;
	tools: InstallableTool[];
	state: "running" | "completed" | "failed" | "unknown";
	stage: string;
	logs: string;
	error: string;
	truncated: boolean;
};
