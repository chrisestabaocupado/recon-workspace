import { type NmapOption, nmapOptions } from "./nmap-options.ts";

type CommandPart = {
	kind: "option" | "target" | "unknown" | "separator";
	args: string[];
	id?: string;
};
type Values = Record<string, string | boolean | string[]>;
export type NmapConfig = {
	targets: string[];
	values: Values;
	unknown: string[];
	source?: {
		parts: CommandPart[];
		targets: string[];
		values: Values;
		unknown: string[];
	};
};
export const emptyNmapConfig = (): NmapConfig => ({
	targets: [],
	values: {},
	unknown: [],
});

// POSIX argument quoting only: no shell execution or expansion.
export function tokenizeCommand(input: string): string[] {
	const tokens: string[] = [];
	let token = "";
	let quote: string | null = null;
	let escaped = false;
	let active = false;
	for (const char of input.trim()) {
		if (escaped) {
			token += char;
			escaped = false;
			active = true;
			continue;
		}
		if (char === "\\" && quote !== "'") {
			escaped = true;
			active = true;
			continue;
		}
		if ((char === "'" || char === '"') && (!quote || quote === char)) {
			quote = quote ? null : char;
			active = true;
			continue;
		}
		if (
			(!quote && /[;|&<>$`]/.test(char)) ||
			(quote === '"' && /[$`]/.test(char))
		) {
			throw new Error(
				"El editor acepta argumentos de Nmap; no admite operadores ni expansiones de shell. Usa comillas simples para un valor literal.",
			);
		}
		if (/\s/.test(char) && !quote) {
			if (active) {
				tokens.push(token);
				token = "";
				active = false;
			}
			continue;
		}
		token += char;
		active = true;
	}
	if (escaped)
		throw new Error(
			"Falta completar el carácter escapado al final del comando.",
		);
	if (quote) throw new Error("Hay una comilla sin cerrar.");
	if (active) tokens.push(token);
	return tokens;
}

function validateValue(option: NmapOption, value: string) {
	if (!value) throw new Error(`Falta el valor de ${option.flags[0]}.`);
	const integerOptions = [
		"random-targets",
		"top-ports",
		"version-intensity",
		"timing",
		"min-hostgroup",
		"max-hostgroup",
		"min-parallelism",
		"max-parallelism",
		"max-retries",
		"data-length",
		"ttl",
		"source-port",
		"mtu",
		"verbose",
		"debug",
	];
	if (integerOptions.includes(option.id) && !/^\d+$/.test(value))
		throw new Error(
			`${option.flags[0]} requiere un número entero no negativo.`,
		);
	const bounds: Record<string, [number, number]> = {
		timing: [0, 5],
		"version-intensity": [0, 9],
		ttl: [0, 255],
		"source-port": [0, 65535],
	};
	const range = bounds[option.id];
	if (range && (Number(value) < range[0] || Number(value) > range[1]))
		throw new Error(
			`${option.flags[0]} debe estar entre ${range[0]} y ${range[1]}.`,
		);
	if (option.id === "ports" && !/^[\w*,:[\]-]+$/.test(value))
		throw new Error("Revisa la lista de puertos de -p.");
}

export function parseNmapCommand(text: string): NmapConfig {
	const tokens = tokenizeCommand(text);
	const executable = tokens.shift()?.toLowerCase();
	if (executable === "sudo")
		throw new Error(
			"No se admite el prefijo sudo. Configura los privilegios en el equipo ejecutor y escribe el comando empezando por nmap.",
		);
	if (executable !== "nmap" && executable !== "nmap.exe")
		throw new Error("El comando debe empezar por nmap.");
	const indexByFlag = new Map(
		nmapOptions.flatMap((option) =>
			option.flags.map((flag) => [flag, option] as const),
		),
	);
	const result = emptyNmapConfig();
	const parts: CommandPart[] = [];
	let positionalOnly = false;
	for (let index = 0; index < tokens.length; index += 1) {
		const token = tokens[index];
		if (token === "--" && !positionalOnly) {
			positionalOnly = true;
			parts.push({ kind: "separator", args: ["--"] });
			continue;
		}
		if (!positionalOnly && token.startsWith("-")) {
			const verbosity = token.match(/^-([vd])(\d+|\1*)$/);
			if (verbosity) {
				const id = verbosity[1] === "v" ? "verbose" : "debug";
				result.values[id] = /^\d+$/.test(verbosity[2])
					? verbosity[2]
					: String(Number(result.values[id] ?? 0) + token.length - 1);
				parts.push({ kind: "option", id, args: [token] });
				continue;
			}
			let option = indexByFlag.get(token);
			let value: string | undefined;
			if (!option && token.startsWith("--") && token.includes("=")) {
				const equals = token.indexOf("=");
				option = indexByFlag.get(token.slice(0, equals));
				value = token.slice(equals + 1);
				if (option && !option.value)
					throw new Error(`${option.flags[0]} no acepta un valor.`);
			}
			if (!option && !token.startsWith("--")) {
				const attached = nmapOptions
					.flatMap((candidate) =>
						candidate.flags
							.filter(
								(flag) =>
									candidate.value &&
									!candidate.id.startsWith("output-") &&
									!flag.startsWith("--") &&
									token.startsWith(flag) &&
									token.length > flag.length,
							)
							.map((flag) => ({ candidate, flag })),
					)
					.sort((a, b) => b.flag.length - a.flag.length)[0];
				if (attached) {
					option = attached.candidate;
					value = token.slice(attached.flag.length);
				}
			}
			if (!option) {
				const args = [token];
				// Unknown arity stays visible in the advanced field; never reorder its value.
				const next = tokens[index + 1];
				if (next && !next.startsWith("-")) {
					args.push(next);
					index += 1;
				}
				result.unknown.push(...args);
				parts.push({ kind: "unknown", args });
				continue;
			}
			const args = [token];
			if (!option.value) result.values[option.id] = true;
			else if (value === undefined && option.optionalValue)
				result.values[option.id] = true;
			else {
				if (value === undefined) {
					const next = tokens[index + 1];
					if (next === undefined || (next.startsWith("-") && next !== "-"))
						throw new Error(`Falta el valor de ${option.flags[0]}.`);
					value = next;
					index += 1;
					args.push(next);
				}
				validateValue(option, value);
				const previous = result.values[option.id];
				result.values[option.id] =
					previous === undefined
						? value
						: Array.isArray(previous)
							? [...previous, value]
							: [String(previous), value];
			}
			parts.push({ kind: "option", id: option.id, args });
		} else {
			result.targets.push(token);
			parts.push({ kind: "target", args: [token] });
		}
	}
	if (result.values.resume && tokens.length !== 2)
		throw new Error(
			"--resume debe usarse solo con su archivo, sin otros parámetros ni objetivos.",
		);
	result.source = {
		parts,
		targets: [...result.targets],
		unknown: [...result.unknown],
		values: structuredClone(result.values),
	};
	return result;
}

export function quoteArg(value: string): string {
	if (/^[\w@%+=:,./-]+$/.test(value)) return value;
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

function optionArgs(
	option: NmapOption,
	value: Values[string] | undefined,
): string[] {
	if (value === undefined || value === false || value === "") return [];
	const flag = option.flags[0];
	if (!option.value || (option.optionalValue && value === true)) return [flag];
	return (Array.isArray(value) ? value : [String(value)]).flatMap((entry) => {
		validateValue(option, entry);
		if (
			["verbose", "debug", "timing"].includes(option.id) ||
			option.optionalValue
		)
			return [`${flag}${entry}`];
		return [flag, entry];
	});
}

export function buildNmapArgs(config: NmapConfig): string[] {
	const same = (a: unknown, b: unknown) =>
		JSON.stringify(a) === JSON.stringify(b);
	if (!config.source) {
		const options = nmapOptions.flatMap((option) =>
			optionArgs(option, config.values[option.id]),
		);
		return [
			...options,
			...config.unknown,
			...(config.targets.some((target) => target.startsWith("-"))
				? ["--"]
				: []),
			...config.targets,
		];
	}
	const source = config.source;
	const originalIds = new Set(
		source.parts
			.filter((part) => part.kind === "option")
			.map((part) => part.id),
	);
	const newOptions = nmapOptions
		.filter((option) => !originalIds.has(option.id))
		.flatMap((option) => optionArgs(option, config.values[option.id]));
	const changedIds = new Set<string>();
	const args: string[] = [];
	let inserted = false;
	let targetsInserted = false;
	let unknownInserted = false;
	for (const part of source.parts) {
		if (!inserted && (part.kind === "separator" || part.kind === "target")) {
			args.push(...newOptions);
			inserted = true;
		}
		if (part.kind === "option" && part.id) {
			if (same(config.values[part.id], source.values[part.id]))
				args.push(...part.args);
			else if (!changedIds.has(part.id)) {
				const option = nmapOptions.find(
					(candidate) => candidate.id === part.id,
				);
				if (option) args.push(...optionArgs(option, config.values[part.id]));
				changedIds.add(part.id);
			}
		} else if (part.kind === "unknown") {
			if (same(config.unknown, source.unknown)) args.push(...part.args);
			else if (!unknownInserted) {
				args.push(...config.unknown);
				unknownInserted = true;
			}
		} else if (part.kind === "target") {
			if (same(config.targets, source.targets)) args.push(...part.args);
			else if (!targetsInserted) {
				if (
					!source.parts.some((item) => item.kind === "separator") &&
					config.targets.some((target) => target.startsWith("-"))
				)
					args.push("--");
				args.push(...config.targets);
				targetsInserted = true;
			}
		} else args.push(...part.args);
	}
	if (!inserted) args.push(...newOptions);
	if (!source.unknown.length) args.push(...config.unknown);
	if (!source.targets.length) {
		if (
			!source.parts.some((item) => item.kind === "separator") &&
			config.targets.some((target) => target.startsWith("-"))
		)
			args.push("--");
		args.push(...config.targets);
	}
	return args;
}

export function buildNmapCommand(config: NmapConfig): string {
	return ["nmap", ...buildNmapArgs(config)].map(quoteArg).join(" ");
}
export function validateNmapArgs(args: string[]): NmapConfig {
	if (
		args.length > 512 ||
		args.some(
			(arg) =>
				typeof arg !== "string" || arg.length > 8192 || arg.includes("\0"),
		) ||
		args.join("").length > 100000
	)
		throw new Error("El comando supera los límites permitidos.");
	return parseNmapCommand(["nmap", ...args].map(quoteArg).join(" "));
}
export function hasNmapTargets(config: NmapConfig): boolean {
	return Boolean(
		config.targets.length ||
			config.values["input-file"] ||
			config.values["random-targets"] !== undefined ||
			config.values.resume ||
			config.values.help ||
			config.values.version ||
			config.values["interface-list"] ||
			config.values["script-help"] ||
			config.values["script-update-db"],
	);
}
export function getNmapSuggestions(
	query: string,
): Array<{ label: string; detail: string }> {
	const needle = query.toLowerCase().replace(/^nmap\s*/, "");
	return nmapOptions
		.flatMap((option) =>
			option.flags.map((flag) => ({
				label: flag,
				detail: `${option.label} · ${option.group}`,
			})),
		)
		.filter(
			(item) =>
				item.label.toLowerCase().startsWith(needle) ||
				item.detail.toLowerCase().includes(needle),
		);
}
export function emptyConfigWithProfile(
	profile: "discovery" | "quick" | "service",
): NmapConfig {
	const config = emptyNmapConfig();
	if (profile === "discovery") config.values["ping-scan"] = true;
	if (profile === "quick") {
		config.values.fast = true;
		config.values["open-only"] = true;
	}
	if (profile === "service") {
		config.values["service-version"] = true;
		config.values["open-only"] = true;
	}
	return config;
}
