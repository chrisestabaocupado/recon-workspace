import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { StringDecoder } from "node:string_decoder";

const packages = {
	searchsploit: "exploitdb",
	nikto: "nikto",
	testssl: "testssl.sh",
	trivy: "trivy",
};
export function installCommands(tools, password = "", root = false) {
	if (
		!Array.isArray(tools) ||
		!tools.length ||
		tools.length > 4 ||
		new Set(tools).size !== tools.length ||
		tools.some((tool) => !Object.hasOwn(packages, tool))
	)
		throw new Error("Herramientas de instalación inválidas.");
	if (
		typeof password !== "string" ||
		password.length > 1024 ||
		/[\r\n\0]/.test(password)
	)
		throw new Error("Contraseña sudo inválida.");
	const wrap = (args) =>
		root
			? ["apt-get", args]
			: [
					"sudo",
					[
						...(password ? ["-S", "-k", "-p", ""] : ["-n"]),
						"--",
						"env",
						"DEBIAN_FRONTEND=noninteractive",
						"LC_ALL=C",
						"apt-get",
						...args,
					],
				];
	return [
		wrap(["update", "--error-on=any"]),
		wrap([
			"install",
			"-y",
			"--no-remove",
			"--no-install-recommends",
			"-o",
			"Dpkg::Options::=--force-confdef",
			"-o",
			"Dpkg::Options::=--force-confold",
			...tools.map((tool) => packages[tool]),
		]),
	];
}
// Buffer whole lines so a password split across chunks never reaches progress output.
export function installationLog(secret, emit) {
	let pending = "",
		dropping = false;
	const output = (text) =>
		emit(secret ? text.replaceAll(secret, "[oculto]") : text);
	return (text, final = false) => {
		pending += text;
		for (;;) {
			const end = pending.indexOf("\n");
			if (end < 0) break;
			if (!dropping && end <= 16384) output(pending.slice(0, end + 1));
			else if (!dropping) output("[Línea demasiado extensa omitida]\n");
			pending = pending.slice(end + 1);
			dropping = false;
		}
		if (pending.length > 16384) {
			pending = "";
			dropping = true;
			output("[Línea demasiado extensa omitida]\n");
		}
		if (final) {
			if (!dropping && pending) output(pending);
			pending = "";
			dropping = false;
		}
	};
}
export function installStep(bin, args, password, emit, spawnProcess = spawn) {
	return new Promise((resolve) => {
		let settled = false;
		const child = spawnProcess(bin, args, {
			shell: false,
			windowsHide: true,
			env: { ...process.env, DEBIAN_FRONTEND: "noninteractive", LC_ALL: "C" },
			stdio: ["pipe", "pipe", "pipe"],
		});
		const streams = [child.stdout, child.stderr].map((stream) => {
			const decoder = new StringDecoder("utf8");
			const log = installationLog(password, (data) =>
				emit({ type: "log", data }),
			);
			stream.on("data", (chunk) => log(decoder.write(chunk)));
			return () => log(decoder.end(), true);
		});
		const done = (code) => {
			if (settled) return;
			settled = true;
			for (const finish of streams) finish();
			resolve(code);
		};
		child.once("error", (error) => {
			emit({
				type: "log",
				data:
					error.code === "ENOENT"
						? `${bin} no está instalado en Kali.\n`
						: "No se pudo iniciar APT en Kali.\n",
			});
			done(1);
		});
		child.once("close", (code) => done(code));
		child.stdin.on("error", () => {});
		child.stdin.end(bin === "sudo" && password ? `${password}\n` : "");
	});
}
export async function installTools(
	request,
	emit,
	step = installStep,
	root = process.getuid?.() === 0,
) {
	let password = request.sudoPassword ?? "";
	const commands = installCommands(request.tools, password, root);
	try {
		for (let i = 0; i < commands.length; i++) {
			emit({
				type: "stage",
				data: i === 0 ? "Actualizando índices APT" : "Instalando herramientas",
			});
			const code = await step(...commands[i], password, emit);
			if (code !== 0) {
				emit({
					type: "done",
					code: code ?? 1,
					error:
						"APT o sudo falló. Revisa el registro: contraseña/permisos sudo, repositorios, conexión o bloqueo de APT. No se reintenta automáticamente.",
				});
				return;
			}
		}
		emit({ type: "done", code: 0, error: "" });
	} finally {
		password = "";
		request.sudoPassword = "";
	}
}
if (!process.argv[1] || process.argv[1].endsWith("remote-install.mjs")) {
	const emit = (event) => process.stdout.write(`${JSON.stringify(event)}\n`);
	try {
		if (
			process.platform !== "linux" ||
			!/^ID=(?:"kali"|kali)$/m.test(readFileSync("/etc/os-release", "utf8"))
		)
			throw new Error("La instalación solo se permite en Kali Linux.");
		let input = "";
		for await (const chunk of process.stdin) {
			input += chunk;
			if (input.length > 15000) throw new Error("Solicitud demasiado extensa.");
		}
		const request = JSON.parse(input);
		input = "";
		await installTools(request, emit);
	} catch {
		emit({
			type: "done",
			code: 1,
			error:
				"Solicitud de instalación inválida o ejecutor distinto de Kali Linux.",
		});
	}
}
