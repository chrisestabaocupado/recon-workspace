export type SshSettings = {
	host: string;
	port: number;
	username: string;
	privateKeyPath: string;
	fingerprint: string;
	passphrase?: string;
};
export type KaliExecutor = Pick<
	SshSettings,
	"host" | "port" | "username" | "fingerprint"
>;
export type KaliAccess = { mode: "ssh"; ssh: SshSettings; kaliToken: string };
export const kaliToolHelp = {
	dig: {
		label: "dig · registros DNS",
		command: "sudo apt install bind9-dnsutils",
		url: "https://www.kali.org/tools/bind9/",
	},
	openssl: {
		label: "OpenSSL · certificados TLS",
		command: "sudo apt install openssl",
		url: "https://www.kali.org/tools/openssl/",
	},
} as const;
export type KaliToolCheck = {
	tool: keyof typeof kaliToolHelp;
	available: boolean;
	status: "available" | "missing" | "error";
	detail: string;
	database: string;
};
export function validateKaliTools(value: unknown): KaliToolCheck[] {
	if (
		!Array.isArray(value) ||
		value.length !== Object.keys(kaliToolHelp).length
	)
		throw new Error(
			"El diagnóstico de herramientas está incompleto. Vuelve a verificar Kali.",
		);
	const seen = new Set<string>();
	return value.map((row) => {
		if (
			!row ||
			!Object.hasOwn(kaliToolHelp, row.tool) ||
			seen.has(row.tool) ||
			!["available", "missing", "error"].includes(row.status) ||
			row.available !== (row.status === "available") ||
			typeof row.detail !== "string" ||
			row.detail.length > 1500 ||
			typeof row.database !== "string" ||
			row.database.length > 1500
		)
			throw new Error("Diagnóstico de herramientas inválido.");
		seen.add(row.tool);
		return {
			tool: row.tool,
			available: row.available,
			status: row.status,
			detail: row.detail,
			database: row.database,
		};
	});
}
export function kaliToolIssue(
	tools: KaliToolCheck[] | undefined,
	tool: string,
): string {
	const check = tools?.find((t) => t.tool === tool);
	if (!check)
		return "Vuelve a comprobar SSH y herramientas para conocer la disponibilidad de esta herramienta.";
	if (check.available) return "";
	const help = kaliToolHelp[check.tool];
	return `${help.label}: ${check.status === "missing" ? "no está instalado o no está en PATH" : "no está disponible"}. ${help.command ? `En Kali: ${help.command}.` : check.detail} Después vuelve a comprobar SSH y herramientas.`;
}
export type KaliVerification = {
	token: string;
	expiresAt: string;
	version: string;
	executor: KaliExecutor;
	settingsSignature: string;
	tools?: KaliToolCheck[];
};

export function validateSsh(value: unknown): asserts value is SshSettings {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error("Configura Kali por SSH desde el navbar.");
	const ssh = value as Partial<SshSettings>;
	if (typeof ssh.host !== "string" || !/^[\w.:%[\]-]{1,255}$/.test(ssh.host))
		throw new Error("Host SSH inválido.");
	if (typeof ssh.username !== "string" || !/^[\w.-]{1,100}$/.test(ssh.username))
		throw new Error("Usuario SSH inválido.");
	if (
		!Number.isInteger(ssh.port) ||
		Number(ssh.port) < 1 ||
		Number(ssh.port) > 65535
	)
		throw new Error("Puerto SSH inválido.");
	if (
		typeof ssh.privateKeyPath !== "string" ||
		!ssh.privateKeyPath ||
		ssh.privateKeyPath.length > 4096
	)
		throw new Error(
			"Indica la ruta de tu clave privada en el servidor de la app.",
		);
	if (
		typeof ssh.fingerprint !== "string" ||
		!/^SHA256:[A-Za-z0-9+/]+$/.test(ssh.fingerprint)
	)
		throw new Error("Verifica y acepta la huella de Kali antes de ejecutar.");
	if (
		ssh.passphrase !== undefined &&
		(typeof ssh.passphrase !== "string" || ssh.passphrase.length > 4096)
	)
		throw new Error("Frase de contraseña inválida.");
}
export function sshSettingsSignature(ssh: SshSettings): string {
	return JSON.stringify([
		ssh.host,
		ssh.port,
		ssh.username,
		ssh.privateKeyPath,
		ssh.fingerprint,
		ssh.passphrase ?? "",
	]);
}
export function executorIdentity(ssh: SshSettings): KaliExecutor {
	const { host, port, username, fingerprint } = ssh;
	return { host, port, username, fingerprint };
}
export function validateExecutor(value: unknown): KaliExecutor {
	const item = value as Partial<SshSettings> | null;
	validateSsh({ ...item, privateKeyPath: "identity-only" });
	return executorIdentity(item as SshSettings);
}
export function requireSshExecution(value: unknown): KaliAccess {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error("Configura Kali por SSH antes de ejecutar.");
	const input = value as Partial<KaliAccess>;
	if (input.mode !== "ssh")
		throw new Error(
			"La ejecución local está deshabilitada. Todas las pruebas se ejecutan en Kali por SSH.",
		);
	validateSsh(input.ssh);
	if (
		typeof input.kaliToken !== "string" ||
		!/^[a-f\d-]{36}$/i.test(input.kaliToken)
	)
		throw new Error("Comprueba la conexión global a Kali antes de ejecutar.");
	return { mode: "ssh", ssh: { ...input.ssh }, kaliToken: input.kaliToken };
}
export function kaliReady(
	verification: KaliVerification | null,
	ssh: SshSettings,
	now = Date.now(),
): boolean {
	return (
		!!verification &&
		Number.isFinite(Date.parse(verification.expiresAt)) &&
		Date.parse(verification.expiresAt) > now &&
		verification.settingsSignature === sshSettingsSignature(ssh)
	);
}
// One automatic attempt on load, then one renewal per expired verification.
// A failed attempt waits for a manual retry instead of looping on the server.
export class KaliAutoVerification {
	private started = false;
	private renewedToken = "";
	claim(
		ssh: SshSettings,
		verification: KaliVerification | null,
		checking: boolean,
		now = Date.now(),
	): boolean {
		if (checking) return false;
		try {
			validateSsh(ssh);
		} catch {
			return false;
		}
		if (!this.started) {
			this.started = true;
			if (!kaliReady(verification, ssh, now)) {
				this.renewedToken = verification?.token ?? "";
				return true;
			}
		}
		if (
			verification &&
			verification.settingsSignature === sshSettingsSignature(ssh) &&
			Number.isFinite(Date.parse(verification.expiresAt)) &&
			Date.parse(verification.expiresAt) <= now &&
			this.renewedToken !== verification.token
		) {
			this.renewedToken = verification.token;
			return true;
		}
		return false;
	}
}
export function validateKaliDiagnostic(value: unknown): string {
	if (!value || typeof value !== "object")
		throw new Error("Kali devolvió un diagnóstico inválido.");
	const info = value as {
		platform?: string;
		distro?: string;
		node?: string;
		nmap?: string;
	};
	if (info.platform !== "linux" || info.distro !== "kali")
		throw new Error(
			"El ejecutor debe ser Kali Linux; no se habilitarán pruebas en este equipo.",
		);
	if (
		typeof info.node !== "string" ||
		Number(info.node.match(/^v(\d+)\./)?.[1] ?? 0) < 22
	)
		throw new Error("Kali necesita Node.js 22 o superior.");
	if (typeof info.nmap !== "string" || !/^Nmap version [\d.]+/.test(info.nmap))
		throw new Error("Nmap no está disponible en Kali.");
	return `Kali Linux · Node ${info.node} · ${info.nmap.slice(0, 300)}`;
}
