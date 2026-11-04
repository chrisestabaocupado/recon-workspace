import type { NmapConfig } from "./nmap-command.ts";

export type GuidedProtocol = "tcp" | "udp" | "both";
export type GuidedPorts = "common" | "default" | "all" | "custom";

const scanTechniques = [
	"syn-scan",
	"connect-scan",
	"ack-scan",
	"window-scan",
	"maimon-scan",
	"udp-scan",
	"null-scan",
	"fin-scan",
	"xmas-scan",
	"idle-scan",
	"sctp-init",
	"sctp-cookie",
	"ip-protocol-scan",
	"ftp-bounce",
	"custom-scan-flags",
];

export function getGuidedProtocol(
	config: NmapConfig,
): GuidedProtocol | "advanced" {
	if (
		scanTechniques.some(
			(id) =>
				!["syn-scan", "connect-scan", "udp-scan"].includes(id) &&
				config.values[id],
		)
	)
		return "advanced";
	const udp = Boolean(config.values["udp-scan"]);
	const tcp = Boolean(
		config.values["syn-scan"] || config.values["connect-scan"],
	);
	return udp ? (tcp ? "both" : "udp") : "tcp";
}

export function setGuidedProtocol(
	config: NmapConfig,
	protocol: GuidedProtocol,
): NmapConfig {
	const values = { ...config.values };
	for (const id of [...scanTechniques, "ping-scan", "list-scan"])
		delete values[id];
	if (protocol !== "udp") values["connect-scan"] = true;
	if (protocol !== "tcp") values["udp-scan"] = true;
	return { ...config, values };
}

export function getGuidedPorts(config: NmapConfig): GuidedPorts | "advanced" {
	const { values } = config;
	if (
		values["top-ports"] ||
		values["port-ratio"] ||
		(values.ports && values.fast)
	)
		return "advanced";
	if (values.ports === "-" || values.ports === "1-65535") return "all";
	if (values.ports !== undefined) return "custom";
	return values.fast ? "common" : "default";
}

export function setGuidedPorts(
	config: NmapConfig,
	mode: GuidedPorts,
): NmapConfig {
	const values = { ...config.values };
	for (const id of ["ports", "fast", "top-ports", "port-ratio"])
		delete values[id];
	if (mode === "common") values.fast = true;
	if (mode === "all") values.ports = "1-65535";
	if (mode === "custom") values.ports = config.values.ports || "80,443";
	return { ...config, values };
}
