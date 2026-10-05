const sensitiveAssignment =
	/(?<![\w.-])((?:[\w.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|community)[\w.-]*)\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;<>&"']+)/gi;
const xmlEscape = (value: string) =>
	value
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&apos;");
export function secretValues(args: string[]): string[] {
	const secrets = new Set<string>();
	for (let index = 0; index < args.length; index += 1) {
		const arg = args[index];
		const scriptValue =
			arg === "--script-args"
				? args[index + 1]
				: arg.startsWith("--script-args=")
					? arg.slice(14)
					: undefined;
		if (scriptValue) secrets.add(scriptValue);
		for (const match of arg.matchAll(sensitiveAssignment)) {
			const value = match[2].replace(/^["']|["']$/g, "");
			if (value && value !== "[REDACTADO]") secrets.add(value);
		}
		for (const match of arg.matchAll(
			/(?<![\w.-])(?:[a-z][a-z\d+.-]*:\/\/)?([^\s/:@]+):([^\s/@]+)@/gi,
		))
			secrets.add(match[2]);
	}
	return [...secrets]
		.flatMap((value) => [value, xmlEscape(value), encodeURIComponent(value)])
		.sort((a, b) => b.length - a.length);
}
export function redactText(text: string, secrets: string[] = []): string {
	let result = text;
	for (const secret of secrets)
		if (secret) result = result.split(secret).join("[REDACTADO]");
	result = result.replace(
		sensitiveAssignment,
		(_match, key: string, value: string) =>
			`${key}${value.startsWith('"') ? '"[REDACTADO]"' : value.startsWith("'") ? "'[REDACTADO]'" : "[REDACTADO]"}`,
	);
	return result.replace(
		/(?<![\w.-])([a-z][a-z\d+.-]*:\/\/)[^\s/:@]+:[^\s/@]+@/gi,
		"$1[REDACTADO]@",
	);
}
export function redactArgs(args: string[]): string[] {
	let scriptValue = false;
	return args.map((arg) => {
		if (scriptValue) {
			scriptValue = false;
			return "[REDACTADO]";
		}
		if (arg === "--script-args") {
			scriptValue = true;
			return arg;
		}
		if (arg.startsWith("--script-args=")) return "--script-args=[REDACTADO]";
		return redactText(arg);
	});
}
export class StreamRedactor {
	private pending = "";
	private secrets: string[];
	constructor(secrets: string[] = []) {
		this.secrets = secrets;
	}
	push(chunk: string): string {
		this.pending += chunk;
		const tail = Math.max(0, ...this.secrets.map((value) => value.length));
		let newline = this.pending.lastIndexOf(
			"\n",
			Math.max(-1, this.pending.length - tail - 1),
		);
		for (const secret of this.secrets) {
			const start = this.pending.lastIndexOf(secret, newline);
			if (start >= 0 && start + secret.length > newline + 1)
				newline = this.pending.lastIndexOf("\n", start - 1);
		}
		if (newline >= 0) {
			const complete = this.pending.slice(0, newline + 1);
			this.pending = this.pending.slice(newline + 1);
			return redactText(complete, this.secrets);
		}
		// Bound pathological lines and keep a suffix large enough for split secrets.
		if (this.pending.length > 100000) {
			const heldTail = Math.max(1024, tail);
			let cut = this.pending.length - heldTail;
			for (const secret of this.secrets) {
				const start = this.pending.lastIndexOf(secret, cut);
				if (start >= 0 && start < cut && start + secret.length > cut)
					cut = start;
			}
			const complete = this.pending.slice(0, cut);
			this.pending = this.pending.slice(cut);
			return redactText(complete, this.secrets);
		}
		return "";
	}
	flush(): string {
		const result = redactText(this.pending, this.secrets);
		this.pending = "";
		return result;
	}
}
