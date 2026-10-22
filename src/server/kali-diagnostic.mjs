import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

export function probeTool(bin, args, spawnProcess = spawn) {
	return new Promise((resolve) => {
		let output = "",
			settled = false;
		const child = spawnProcess(bin, args, {
			shell: false,
			windowsHide: true,
			stdio: ["ignore", "pipe", "pipe"],
		});
		const done = (status, detail) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({ status, detail: detail.slice(0, 1500) });
		};
		const timer = setTimeout(() => {
			child.kill("SIGKILL");
			done("error", "La comprobación de versión agotó 5 segundos.");
		}, 5000);
		for (const stream of [child.stdout, child.stderr])
			stream.on("data", (chunk) => {
				output = (output + chunk.toString()).slice(0, 1500);
			});
		child.once("error", (error) =>
			done(
				error.code === "ENOENT" ? "missing" : "error",
				error.code === "ENOENT"
					? `${bin} no está instalado o no está en PATH.`
					: error.message,
			),
		);
		child.once("close", (code) => {
			done(
				code === 0 ? "available" : "error",
				output || `${bin} terminó con código ${code}.`,
			);
		});
	});
}
export async function inspectKaliTools(probe = probeTool) {
	return Promise.all(
		[
			["dig", "dig", ["-v"]],
			["openssl", "openssl", ["version"]],
		].map(async ([tool, bin, args]) => {
			const result = await probe(bin, args);
			return {
				tool,
				...result,
				available: result.status === "available",
				database:
					"Comprobación local del ejecutable, sin consultas a objetivos ni fuentes externas.",
			};
		}),
	);
}

if (!process.argv[1] || process.argv[1].endsWith("kali-diagnostic.mjs")) {
	const release = readFileSync("/etc/os-release", "utf8");
	const distro = release.match(/^ID=(?:"([^"]+)"|([^\s]+))$/m);
	const distroId = distro?.[1] ?? distro?.[2] ?? "";
	const nmap =
		process.platform === "linux" && distroId === "kali"
			? spawnSync("nmap", ["--version"], {
					encoding: "utf8",
					timeout: 5000,
					maxBuffer: 16384,
				})
			: undefined;
	console.log(
		JSON.stringify({
			platform: process.platform,
			distro: distroId,
			node: process.version,
			nmap: nmap?.status === 0 ? nmap.stdout.split("\n")[0] : "",
			tools:
				process.platform === "linux" &&
				distroId === "kali" &&
				nmap?.status === 0
					? await inspectKaliTools()
					: [],
		}),
	);
}
