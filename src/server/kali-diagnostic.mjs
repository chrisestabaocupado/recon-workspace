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
			// SearchSploit documents exit 2 for its help screen, not an execution failure.
			const help =
				bin === "searchsploit" &&
				args.length === 1 &&
				["-h", "--help"].includes(args[0]) &&
				code === 2 &&
				/Usage:\s+searchsploit\b/i.test(output);
			done(
				code === 0 || help ? "available" : "error",
				output || `${bin} terminó con código ${code}.`,
			);
		});
	});
}
export async function inspectKaliTools(probe = probeTool, request = fetch) {
	const binaries = await Promise.all(
		[
			["searchsploit", "searchsploit", ["-h"]],
			["nikto", "nikto", ["-Version"]],
			["testssl", "testssl", ["--version"]],
			["trivy", "trivy", ["--version"]],
		].map(async ([tool, bin, args]) => {
			const result = await probe(bin, args);
			return {
				tool,
				...result,
				available: result.status === "available",
				database:
					"Comprobación del ejecutable; la presencia y actualidad de su base deben revisarse antes de consultar.",
			};
		}),
	);
	let local;
	try {
		const response = await request("http://127.0.0.1:5000/api/dbInfo", {
			signal: AbortSignal.timeout(5000),
			redirect: "error",
		});
		if (!response.ok)
			throw new Error(`API local respondió HTTP ${response.status}.`);
		const reader = response.body?.getReader();
		if (!reader) throw new Error("API local sin respuesta JSON.");
		let bytes = 0;
		const chunks = [];
		try {
			for (;;) {
				const { done, value } = await reader.read();
				if (done) break;
				bytes += value.byteLength;
				if (bytes > 16384) {
					await reader.cancel();
					throw new Error("Diagnóstico local supera 16 KB.");
				}
				chunks.push(Buffer.from(value));
			}
		} finally {
			reader.releaseLock();
		}
		const raw = Buffer.concat(chunks).toString("utf8");
		const info = JSON.parse(raw);
		if (!info || typeof info !== "object")
			throw new Error("API local no devolvió un diagnóstico JSON válido.");
		local = {
			tool: "cve",
			status: "available",
			available: true,
			detail: "API local disponible en 127.0.0.1:5000",
			database: raw.slice(0, 1500),
		};
	} catch (error) {
		local = {
			tool: "cve",
			status: "error",
			available: false,
			detail:
				`Configura y carga cve-search en 127.0.0.1:5000. ${error.message}`.slice(
					0,
					1500,
				),
			database: "Servicio local no disponible; puedes consultar NVD en línea.",
		};
	}
	return [
		...binaries,
		local,
		{
			tool: "nvd",
			status: "available",
			available: true,
			detail:
				"No requiere instalar un ejecutable. La conectividad HTTPS se comprueba al consultar.",
			database: "API pública NVD; requiere salida HTTPS desde Kali.",
		},
	];
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
