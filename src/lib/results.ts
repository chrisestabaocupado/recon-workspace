import { XMLParser, XMLValidator } from "fast-xml-parser";

export type ObservedPort = {
	port: number;
	protocol: string;
	state: string;
	service: string;
	product?: string;
	version?: string;
};
export type ObservedHost = {
	address: string;
	hostname?: string;
	status?: string;
	ports: ObservedPort[];
};
// Agrupa observaciones del mismo reporte; el XML original conserva cada intento.
export function mergeObservedHosts(hosts: ObservedHost[]): ObservedHost[] {
	const merged = new Map<string, ObservedHost>();
	for (const observation of hosts) {
		const address = observation.address.trim();
		const key = address.toLowerCase();
		const previous = merged.get(key);
		const ports = new Map<string, ObservedPort>();
		for (const port of previous?.ports ?? [])
			ports.set(`${port.protocol.toLowerCase()}:${port.port}`, { ...port });
		for (const port of observation.ports) {
			const portKey = `${port.protocol.toLowerCase()}:${port.port}`;
			const prior = ports.get(portKey);
			ports.set(portKey, {
				...port,
				protocol: port.protocol.toLowerCase(),
				service:
					port.service === "unknown" && prior?.state === port.state
						? prior.service
						: port.service,
				product:
					port.product ??
					(prior?.state === port.state ? prior.product : undefined),
				version:
					port.version ??
					(prior?.state === port.state ? prior.version : undefined),
			});
		}
		merged.set(key, {
			address: previous?.address ?? address,
			hostname: observation.hostname || previous?.hostname,
			status: observation.status ?? previous?.status,
			ports: [...ports.values()].sort(
				(a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol),
			),
		});
	}
	return [...merged.values()];
}

type XmlNode = Record<string, unknown>;
const node = (value: unknown): XmlNode =>
	value && typeof value === "object" ? (value as XmlNode) : {};
const list = (value: unknown): unknown[] =>
	value === undefined ? [] : Array.isArray(value) ? value : [value];
const attr = (value: XmlNode, key: string): string | undefined =>
	typeof value[`@_${key}`] === "string"
		? (value[`@_${key}`] as string)
		: undefined;

function fromXml(report: string): ObservedHost[] {
	const start = report.indexOf("<nmaprun");
	const end = report.lastIndexOf("</nmaprun>");
	if (start < 0 || end < start)
		throw new Error("El XML Nmap está incompleto o no contiene nmaprun.");
	if (/<!ENTITY/i.test(report))
		throw new Error(
			"El reporte contiene declaraciones de entidades no compatibles.",
		);
	const xml = report.slice(start, end + "</nmaprun>".length);
	if (XMLValidator.validate(xml) !== true)
		throw new Error("El XML Nmap no es válido.");
	const parsed = new XMLParser({
		ignoreAttributes: false,
		parseAttributeValue: false,
		parseTagValue: false,
		processEntities: false,
	}).parse(xml) as { nmaprun?: XmlNode };
	return list(node(parsed.nmaprun).host).map((entry) => {
		const host = node(entry);
		const addresses = list(host.address).map(node);
		const address =
			addresses.find((item) =>
				["ipv4", "ipv6"].includes(attr(item, "addrtype") ?? ""),
			) ??
			addresses[0] ??
			{};
		const ports = list(node(host.ports).port)
			.map((entry) => {
				const port = node(entry);
				const service = node(port.service);
				return {
					port: Number(attr(port, "portid")),
					protocol: attr(port, "protocol") ?? "?",
					state: attr(node(port.state), "state") ?? "unknown",
					service: attr(service, "name") ?? "unknown",
					product: attr(service, "product"),
					version:
						[attr(service, "version"), attr(service, "extrainfo")]
							.filter(Boolean)
							.join(" ") || undefined,
				};
			})
			.filter(
				(port) =>
					Number.isInteger(port.port) && port.port >= 0 && port.port <= 65535,
			);
		return {
			address: attr(address, "addr") ?? "desconocido",
			hostname: attr(node(list(node(host.hostnames).hostname)[0]), "name"),
			status: attr(node(host.status), "state"),
			ports,
		};
	});
}
function fromText(report: string): ObservedHost[] {
	const hosts: ObservedHost[] = [];
	let current: ObservedHost | undefined;
	for (const line of report.split(/\r?\n/)) {
		const hostMatch = line.match(/^Nmap scan report for (.+)$/);
		if (hostMatch) {
			const raw = hostMatch[1].trim();
			const addressMatch = raw.match(/^(.*?)\s+\(([^)]+)\)$/);
			current = {
				address: addressMatch?.[2] ?? raw,
				hostname: addressMatch?.[1] || undefined,
				ports: [],
			};
			hosts.push(current);
			continue;
		}
		if (!current) continue;
		const statusMatch = line.match(/^Host is (up|down)\b/i);
		if (statusMatch) {
			current.status = statusMatch[1].toLowerCase();
			continue;
		}
		const portMatch = line.match(
			/^\s*(\d+)\/(tcp|udp|sctp)\s+([\w|/-]+)\s+(\S+)(?:\s+(.*))?$/i,
		);
		if (portMatch)
			current.ports.push({
				port: Number(portMatch[1]),
				protocol: portMatch[2].toLowerCase(),
				state: portMatch[3].toLowerCase(),
				service: portMatch[4],
				version: portMatch[5]?.trim() || undefined,
			});
	}
	return hosts;
}
export function readNmapReport(report: string): ObservedHost[] {
	if (report.length > 8 * 1024 * 1024)
		throw new Error("El reporte supera 8 MB.");
	if (report.includes("<nmaprun") || report.trimStart().startsWith("<?xml"))
		return mergeObservedHosts(fromXml(report));
	if (!/^Nmap scan report for |Nmap done:/m.test(report))
		throw new Error("No se reconoce un reporte Nmap XML o de texto normal.");
	return mergeObservedHosts(fromText(report));
}
export function parseNmapResults(report: string): ObservedHost[] {
	try {
		return readNmapReport(report);
	} catch {
		return [];
	}
}
