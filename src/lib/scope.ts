import ipaddr from "ipaddr.js";
import { type NmapConfig, validateNmapArgs } from "./nmap-command.ts";
import { redactText } from "./redaction.ts";

export const scopeTechniques = {
	discovery: "Descubrimiento de hosts",
	tcp: "Enumeración TCP",
	udp: "Enumeración UDP",
	services: "Identificación de servicios y versiones",
	os: "Detección de sistema operativo",
} as const;
export type ScopePlan = {
	version: 1;
	revision: number;
	status: "draft" | "approved" | "paused" | "closed";
	organization: string;
	objective: string;
	assessmentType: "internal" | "external";
	assessor: string;
	authorizer: string;
	authorizationReference: string;
	approvalAttested: boolean;
	passiveRecon: boolean;
	approvedAt?: string;
	includes: string[];
	excludes: string[];
	windowStart: string;
	windowEnd: string;
	contactName: string;
	contactChannel: string;
	incidentName: string;
	incidentChannel: string;
	sourceDescription: string;
	techniques: Record<keyof typeof scopeTechniques, boolean>;
	allowedPorts: string;
	maxHosts: number;
	maxRate: number;
	maxDurationSeconds: number;
	prohibitedActivities: string;
	stopConditions: string;
	dataHandling: string;
	retentionDays: number;
	deliverables: string;
	notes: string;
};
export const newScopePlan = (): ScopePlan => ({
	version: 1,
	revision: 1,
	status: "draft",
	organization: "",
	objective: "",
	assessmentType: "internal",
	assessor: "",
	authorizer: "",
	authorizationReference: "",
	approvalAttested: false,
	passiveRecon: false,
	includes: [],
	excludes: [],
	windowStart: "",
	windowEnd: "",
	contactName: "",
	contactChannel: "",
	incidentName: "",
	incidentChannel: "",
	sourceDescription: "",
	techniques: {
		discovery: true,
		tcp: true,
		udp: false,
		services: true,
		os: false,
	},
	allowedPorts: "1-65535",
	maxHosts: 16,
	maxRate: 100,
	maxDurationSeconds: 600,
	prohibitedActivities:
		"Denegación de servicio, explotación, fuerza bruta, modificación de datos, ingeniería social y acceso a activos fuera del alcance.",
	stopConditions:
		"Detener ante degradación del servicio, exposición inesperada de datos sensibles, un objetivo fuera del alcance o solicitud del contacto de incidentes. Registrar lo ocurrido y obtener autorización antes de reanudar.",
	dataHandling:
		"Evidencia confidencial. Guardar solo lo necesario, depurar credenciales y entregar únicamente a los destinatarios acordados. El navegador guarda datos localmente; exportaciones y borrado se realizan de forma manual.",
	retentionDays: 30,
	deliverables:
		"Inventario de hosts y servicios, comandos y fechas de ejecución, limitaciones, evidencia y recomendaciones de siguientes pasos.",
	notes: "",
});

type AddressRange = {
	kind: string;
	first: bigint;
	last: bigint;
	count: bigint;
};
export function addressRange(value: string): AddressRange | null {
	const [address, prefixText, extra] = value.split("/");
	if (extra !== undefined || address.includes("%")) return null;
	if (
		!address.includes(":") &&
		!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(address)
	)
		return null;
	try {
		const parsed = ipaddr.parse(address);
		if (
			parsed.kind() === "ipv6" &&
			(parsed as ipaddr.IPv6).isIPv4MappedAddress()
		)
			return null;
		const bits = parsed.kind() === "ipv4" ? 32 : 128;
		const prefix = prefixText === undefined ? bits : Number(prefixText);
		if (prefixText !== undefined && !/^\d+$/.test(prefixText)) return null;
		if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
		const numeric = parsed
			.toByteArray()
			.reduce((result, byte) => (result << 8n) + BigInt(byte), 0n);
		const count = 1n << BigInt(bits - prefix);
		const first = (numeric / count) * count;
		return { kind: parsed.kind(), first, last: first + count - 1n, count };
	} catch {
		return null;
	}
}
export function normalizeScopeEntry(value: string): string {
	const entry = value.trim().toLowerCase().replace(/\.$/, "");
	if (addressRange(entry)) return entry;
	if (
		entry.length <= 253 &&
		!/^[\d.-]+$/.test(entry) &&
		entry
			.split(".")
			.every((part) => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/.test(part))
	)
		return entry;
	throw new Error(
		`Objetivo no compatible: ${value}. Usa IP, CIDR o nombre DNS exacto; sin URLs, comodines ni rangos de Nmap.`,
	);
}
export function scopeLines(text: string): string[] {
	return [
		...new Set(
			text
				.split(/[\s,;]+/)
				.map((line) => line.trim())
				.filter(Boolean)
				.map(normalizeScopeEntry),
		),
	];
}
function within(candidate: AddressRange, allowed: AddressRange) {
	return (
		candidate.kind === allowed.kind &&
		candidate.first >= allowed.first &&
		candidate.last <= allowed.last
	);
}
function overlaps(a: AddressRange, b: AddressRange) {
	return a.kind === b.kind && a.first <= b.last && b.first <= a.last;
}
export function targetDecision(
	target: string,
	plan: ScopePlan,
): { allowed: boolean; reason: string; count: bigint; dns: boolean } {
	let normalized: string;
	try {
		normalized = normalizeScopeEntry(target);
	} catch (error) {
		return {
			allowed: false,
			reason: error instanceof Error ? error.message : "Objetivo inválido",
			count: 0n,
			dns: false,
		};
	}
	const range = addressRange(normalized);
	const excluded = plan.excludes.some((entry) => {
		const exclusion = addressRange(entry);
		return range && exclusion
			? overlaps(range, exclusion)
			: entry === normalized;
	});
	if (excluded)
		return {
			allowed: false,
			reason:
				"Coincide o se solapa con una exclusión. Divide el rango en destinos permitidos.",
			count: range?.count ?? 1n,
			dns: !range,
		};
	const included = plan.includes.some((entry) => {
		const inclusion = addressRange(entry);
		return range && inclusion ? within(range, inclusion) : entry === normalized;
	});
	return {
		allowed: included,
		reason: included ? "Dentro del alcance" : "No está incluido en el alcance",
		count: range?.count ?? 1n,
		dns: !range,
	};
}
export function validateScopePlan(value: unknown): ScopePlan {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error("Plan de alcance inválido.");
	const item = value as Record<string, unknown>;
	const defaults = newScopePlan();
	const result = { ...defaults };
	for (const key of Object.keys(defaults) as (keyof ScopePlan)[]) {
		if (
			typeof defaults[key] === "string" &&
			!["status", "assessmentType"].includes(key)
		) {
			const text = item[key];
			if (typeof text !== "string" || text.length > 8192)
				throw new Error(`Plan: campo ${key} inválido.`);
			Object.assign(result, { [key]: redactText(text) });
		}
	}
	if (
		item.version !== 1 ||
		!Number.isSafeInteger(item.revision) ||
		Number(item.revision) < 1
	)
		throw new Error("Versión de plan inválida.");
	if (!["draft", "approved", "paused", "closed"].includes(String(item.status)))
		throw new Error("Estado de plan inválido.");
	if (item.assessmentType !== "internal" && item.assessmentType !== "external")
		throw new Error("Tipo de evaluación inválido.");
	if (typeof item.approvalAttested !== "boolean")
		throw new Error("Confirmación de autorización inválida.");
	result.revision = Number(item.revision);
	result.status = item.status as ScopePlan["status"];
	result.assessmentType = item.assessmentType;
	result.approvalAttested = item.approvalAttested;
	if (item.passiveRecon !== undefined && typeof item.passiveRecon !== "boolean")
		throw new Error("Permiso de reconocimiento pasivo inválido.");
	result.passiveRecon = item.passiveRecon === true;
	for (const key of ["includes", "excludes"] as const) {
		if (
			!Array.isArray(item[key]) ||
			item[key].length > 1000 ||
			item[key].some((entry) => typeof entry !== "string")
		)
			throw new Error(`Plan: ${key} inválido.`);
		result[key] = [
			...new Set((item[key] as string[]).map(normalizeScopeEntry)),
		];
	}
	for (const [key, maximum] of [
		["maxHosts", 4096],
		["maxRate", 100000],
		["maxDurationSeconds", 86400],
		["retentionDays", 3650],
	] as const) {
		if (
			!Number.isSafeInteger(item[key]) ||
			Number(item[key]) < (key === "maxDurationSeconds" ? 5 : 1) ||
			Number(item[key]) > maximum
		)
			throw new Error(`Plan: ${key} fuera de rango.`);
		result[key] = Number(item[key]);
	}
	if (!item.techniques || typeof item.techniques !== "object")
		throw new Error("Técnicas del plan inválidas.");
	for (const key of Object.keys(
		scopeTechniques,
	) as (keyof typeof scopeTechniques)[]) {
		const enabled = (item.techniques as Record<string, unknown>)[key];
		if (typeof enabled !== "boolean")
			throw new Error("Técnicas del plan inválidas.");
		result.techniques[key] = enabled;
	}
	for (const key of ["windowStart", "windowEnd", "approvedAt"] as const) {
		const text = item[key];
		if (
			text !== undefined &&
			text !== "" &&
			(typeof text !== "string" || !Number.isFinite(Date.parse(text)))
		)
			throw new Error(`Plan: fecha ${key} inválida.`);
	}
	result.approvedAt =
		typeof item.approvedAt === "string" ? item.approvedAt : undefined;
	portRanges(result.allowedPorts);
	if (
		result.status === "approved" &&
		(!result.approvedAt || !result.approvalAttested)
	)
		throw new Error("El plan aprobado no contiene confirmación y fecha.");
	return result;
}
export function approvalIssues(plan: ScopePlan, now = Date.now()): string[] {
	const errors: string[] = [];
	for (const [key, label] of [
		["organization", "organización o propietario"],
		["objective", "objetivo de la evaluación"],
		["assessor", "responsable de las pruebas"],
		["authorizer", "persona que autoriza"],
		["authorizationReference", "referencia de la autorización escrita"],
		["contactName", "contacto de coordinación"],
		["contactChannel", "canal de coordinación"],
		["incidentName", "contacto de incidentes"],
		["incidentChannel", "canal de incidentes"],
		["sourceDescription", "origen de las pruebas y conectividad"],
		["stopConditions", "criterios de parada"],
		["dataHandling", "manejo y destinatarios de la evidencia"],
		["deliverables", "entregables"],
		["prohibitedActivities", "actividades prohibidas"],
	] as const)
		if (!plan[key].trim()) errors.push(`Completa ${label}.`);
	if (!plan.includes.length)
		errors.push("Incluye al menos un activo autorizado.");
	if (
		!plan.windowStart ||
		!plan.windowEnd ||
		Date.parse(plan.windowStart) >= Date.parse(plan.windowEnd)
	)
		errors.push("Define una ventana válida de inicio y fin.");
	else if (Date.parse(plan.windowEnd) <= now)
		errors.push("La ventana de pruebas ya terminó.");
	if (!plan.passiveRecon && !Object.values(plan.techniques).some(Boolean))
		errors.push("Selecciona al menos una técnica permitida.");
	return errors;
}
export function approveScopePlan(
	plan: ScopePlan,
	attested: boolean,
	now = Date.now(),
): ScopePlan {
	const validated = validateScopePlan(plan);
	const issues = approvalIssues(validated, now);
	if (!attested)
		issues.push(
			"Confirma que dispones de la autorización escrita de los responsables de los activos, incluidos terceros cuando corresponda.",
		);
	if (issues.length) throw new Error(issues.join("\n"));
	return {
		...validated,
		status: "approved",
		approvalAttested: true,
		approvedAt: new Date(now).toISOString(),
	};
}
export function reviseScopePlan(plan: ScopePlan): ScopePlan {
	return {
		...plan,
		revision: plan.revision + 1,
		status: "draft",
		approvalAttested: false,
		approvedAt: undefined,
	};
}
export function portRanges(expression: string): [number, number][] {
	if (!expression || expression.length > 4096)
		throw new Error(
			"Indica los puertos permitidos: números o rangos separados por comas.",
		);
	return expression.split(",").map((entry) => {
		const match = entry.trim().match(/^(\d+)(?:-(\d+))?$/);
		const start = Number(match?.[1]);
		const end = Number(match?.[2] ?? match?.[1]);
		if (
			!match ||
			!Number.isInteger(start) ||
			start < 0 ||
			end > 65535 ||
			end < start
		)
			throw new Error(
				"Lista de puertos inválida. Usa, por ejemplo, 22,80,443 o 1-1024.",
			);
		return [start, end];
	});
}
function values(config: NmapConfig, id: string): string[] {
	const item = config.values[id];
	return item === undefined ? [] : Array.isArray(item) ? item : [String(item)];
}
export function scopedCommandIssues(
	args: string[],
	plan?: ScopePlan,
	timeoutSeconds = 600,
	now = Date.now(),
): string[] {
	const config = validateNmapArgs(args);
	if (
		!config.targets.length &&
		args.length === 1 &&
		["--version", "-V", "--help", "-h", "--iflist"].includes(args[0])
	)
		return [];
	if (!plan)
		return [
			"Configura y aprueba el plan en Alcance y planificación antes de ejecutar.",
		];
	const issues = approvalIssues(plan, now);
	if (plan.status !== "approved" || !plan.approvalAttested || !plan.approvedAt)
		issues.unshift(
			"El plan debe estar aprobado. Los planes en borrador, pausados o cerrados no permiten ejecuciones.",
		);
	if (now < Date.parse(plan.windowStart) || now >= Date.parse(plan.windowEnd))
		issues.push("La ejecución está fuera de la ventana autorizada.");
	if (
		timeoutSeconds > plan.maxDurationSeconds ||
		now + timeoutSeconds * 1000 > Date.parse(plan.windowEnd)
	)
		issues.push(
			"Reduce el timeout para respetar la duración máxima y el final de la ventana.",
		);
	if (config.unknown.length)
		issues.push(
			"Las opciones sin mapear no permiten verificar las reglas del plan. Revisa los argumentos avanzados.",
		);
	const blocked = [
		"input-file",
		"random-targets",
		"resume",
		"exclude-file",
		"resolve-all",
		"data-dir",
		"script-args-file",
		"scripts",
		"default-scripts",
		"script-args",
		"script-update-db",
		"script-help",
		"aggressive",
		"dns-servers",
		"proxies",
		"decoys",
		"source-ip",
		"spoof-mac",
		"idle-scan",
		"ftp-bounce",
		"ip-protocol-scan",
		"sctp-init",
		"sctp-cookie",
		"custom-scan-flags",
		"traceroute",
	];
	for (const id of blocked)
		if (config.values[id] !== undefined)
			issues.push(
				`La opción ${id} requiere una validación específica de destinos o técnicas que este MVP todavía no implementa.`,
			);
	if (!config.targets.length)
		issues.push("Escribe objetivos explícitos para comprobar el alcance.");
	let count = 0n;
	for (const target of config.targets) {
		const decision = targetDecision(target, plan);
		if (!decision.allowed) issues.push(`${target}: ${decision.reason}.`);
		count += decision.count;
		const range = addressRange(target);
		if (range && (range.kind === "ipv6") !== Boolean(config.values.ipv6))
			issues.push(
				`${target}: la familia de direcciones debe coincidir con -6. Separa IPv4 e IPv6 en ejecuciones distintas.`,
			);
	}
	if (count > BigInt(plan.maxHosts))
		issues.push(
			`El comando incluye ${count.toString()} direcciones; el máximo por ejecución es ${plan.maxHosts}.`,
		);
	const discoveryOnly = Boolean(
		config.values["ping-scan"] || config.values["list-scan"],
	);
	if (
		(!config.values["skip-discovery"] || discoveryOnly) &&
		!plan.techniques.discovery
	)
		issues.push(
			"El plan no permite descubrimiento. Usa -Pn para un análisis de puertos sin descubrimiento previo.",
		);
	const explicitTcp = [
		"syn-scan",
		"connect-scan",
		"ack-scan",
		"window-scan",
		"maimon-scan",
		"null-scan",
		"fin-scan",
		"xmas-scan",
	].some((id) => config.values[id]);
	if (
		!discoveryOnly &&
		(!config.values["udp-scan"] || explicitTcp) &&
		!plan.techniques.tcp
	)
		issues.push("El plan no permite enumeración TCP.");
	if (config.values["udp-scan"] && !plan.techniques.udp)
		issues.push("El plan no permite enumeración UDP.");
	if (config.values["service-version"] && !plan.techniques.services)
		issues.push("El plan no permite identificación de versiones (-sV).");
	if (config.values["os-detection"] && !plan.techniques.os)
		issues.push("El plan no permite detección de sistema operativo (-O).");
	const rates = values(config, "max-rate");
	if (
		rates.length !== 1 ||
		!Number.isFinite(Number(rates[0])) ||
		Number(rates[0]) <= 0 ||
		Number(rates[0]) > plan.maxRate
	)
		issues.push(
			`Indica --max-rate con un único valor entre 1 y ${plan.maxRate}.`,
		);
	if (values(config, "min-rate").some((rate) => Number(rate) > plan.maxRate))
		issues.push("--min-rate supera el límite del plan.");
	if (plan.allowedPorts !== "1-65535" && !discoveryOnly) {
		if (!config.values["skip-discovery"])
			issues.push(
				"Con puertos restringidos usa -Pn para evitar sondas de descubrimiento en otros puertos.",
			);
		const ports = values(config, "ports");
		if (
			ports.length !== 1 ||
			config.values.fast ||
			config.values["top-ports"] ||
			config.values["port-ratio"]
		)
			issues.push(
				"El plan restringe los puertos: usa una lista explícita -p, sin -F, --top-ports ni --port-ratio.",
			);
		else {
			try {
				const allowed = portRanges(plan.allowedPorts);
				const requested = portRanges(
					ports[0].replace(/[TUS]:/g, "").replace(/^-$/, "1-65535"),
				);
				for (const [first, last] of requested) {
					const merged = [...allowed].sort((a, b) => a[0] - b[0]);
					let next = first;
					for (const [start, end] of merged)
						if (start <= next && end >= next) next = end + 1;
					if (next <= last)
						issues.push(
							`Los puertos ${first}-${last} exceden los permitidos en el plan.`,
						);
				}
			} catch {
				issues.push(
					"La expresión de -p no se puede verificar contra los puertos del plan. Usa números y rangos.",
				);
			}
		}
	}
	return [...new Set(issues)];
}

export function pinResolvedScope(
	args: string[],
	plan: ScopePlan,
	resolved: Record<string, string[]>,
	timeoutSeconds: number,
	now = Date.now(),
): string[] {
	const config = validateNmapArgs(args);
	const family = config.values.ipv6 ? "ipv6" : "ipv4";
	const targetNames = [
		...new Set(config.targets.filter((target) => !addressRange(target))),
	];
	const excludedNames = plan.excludes.filter((entry) => !addressRange(entry));
	for (const name of [...targetNames, ...excludedNames]) {
		if (!Array.isArray(resolved[name]) || !resolved[name].length)
			throw new Error(
				`No se pudo resolver ${name} para ${family}. No se puede comprobar el alcance.`,
			);
		for (const address of resolved[name]) {
			if (
				typeof address !== "string" ||
				address.includes("/") ||
				addressRange(address)?.kind !== family
			)
				throw new Error(
					"El ejecutor devolvió una dirección DNS inválida o de otra familia.",
				);
		}
	}
	const effectivePlan = {
		...plan,
		includes: [...plan.includes],
		excludes: [
			...plan.excludes,
			...excludedNames.flatMap((name) => resolved[name]),
		],
	};
	const pinned = new Map<string, string>();
	for (const name of targetNames) {
		if (!targetDecision(name, plan).allowed)
			throw new Error(`${name} no está autorizado.`);
		for (const address of resolved[name]) {
			if (
				!targetDecision(address, {
					...effectivePlan,
					includes: [...effectivePlan.includes, address],
				}).allowed
			)
				throw new Error(
					`${name} resuelve a ${address}, que coincide con una exclusión. Revisa el plan.`,
				);
		}
		const first = resolved[name][0];
		pinned.set(name, first);
		effectivePlan.includes.push(first);
	}
	const result =
		config.source?.parts.flatMap((part) =>
			part.kind === "target"
				? part.args.map((target) => pinned.get(target) ?? target)
				: part.args,
		) ?? args;
	const issues = scopedCommandIssues(
		result,
		effectivePlan,
		timeoutSeconds,
		now,
	);
	if (issues.length) throw new Error(issues.join("\n"));
	return result;
}
