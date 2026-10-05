import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import http from "node:http";
import net, { isIP } from "node:net";
import os from "node:os";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import { parseNiktoTarget } from "../lib/web-target.mjs";

const LIMIT = 2 * 1024 * 1024;
// Arguments are fixed by adapters; all operator input arrives as JSON on stdin.
export function toolArguments(q, report) {
	if (
		!Number.isInteger(q.timeoutSeconds) ||
		q.timeoutSeconds < 5 ||
		q.timeoutSeconds > 180
	)
		throw new Error("Timeout inválido.");
	if (q.tool === "searchsploit") {
		if (q.cve) {
			if (!/^CVE-\d{4}-\d{4,}$/.test(q.cve)) throw new Error("CVE inválido.");
			return ["searchsploit", ["-j", "--cve", q.cve]];
		}
		if (
			typeof q.product !== "string" ||
			!q.product.trim() ||
			[q.product, q.version].some(
				(v) => typeof v !== "string" || v.startsWith("-") || /[\r\n\0]/.test(v),
			)
		)
			throw new Error("Producto inválido.");
		return [
			"searchsploit",
			["-j", q.product, ...(q.version ? [q.version] : [])],
		];
	}
	if (q.tool === "trivy") {
		if (
			typeof q.path !== "string" ||
			!q.path.startsWith("/") ||
			/[\r\n\0]/.test(q.path)
		)
			throw new Error("Ruta Kali inválida.");
		return [
			"trivy",
			[
				"fs",
				"--scanners",
				"vuln",
				"--offline-scan",
				"--skip-db-update",
				"--skip-java-db-update",
				"--skip-check-update",
				"--skip-version-check",
				"--format",
				"json",
				"--timeout",
				`${q.timeoutSeconds}s`,
				"--",
				q.path,
			],
		];
	}
	const web = q.tool === "nikto" ? parseNiktoTarget(q) : null;
	if (
		(!web && !isIP(q.target)) ||
		!Number.isInteger(q.port) ||
		q.port < 1 ||
		q.port > 65535
	)
		throw new Error("Destino inválido.");
	const host = isIP(q.target) === 6 ? `[${q.target}]` : q.target;
	if (q.tool === "nikto")
		return [
			"nikto",
			[
				"-h",
				`${web.tls ? "https" : "http"}://${web.host.includes(":") ? `[${web.host}]` : web.host}:${web.port}`,
				web.tls ? "-ssl" : "-nossl",
				...(web.root ? ["-root", web.root] : []),
				"-nointeractive",
				"-ask",
				"no",
				"-nolookup",
				"-nocheck",
				"-Pause",
				"1",
				"-Tuning",
				"123b",
				"-maxtime",
				`${Math.max(1, q.timeoutSeconds - 15)}s`,
				"-timeout",
				"10",
				"-Format",
				"json",
				"-output",
				report,
			],
		];
	if (q.tool === "testssl")
		return [
			"testssl",
			[
				"--quiet",
				"--warnings",
				"batch",
				"--color",
				"0",
				"--connect-timeout",
				"5",
				"--openssl-timeout",
				"5",
				"--jsonfile",
				report,
				`${host}:${q.port}`,
			],
		];
	throw new Error("Herramienta no compatible.");
}
// A loopback proxy pins the TCP destination while Nikto retains the domain in
// HTTP Host and TLS SNI. It accepts only this host/port, with no redirects.
export async function niktoProxy(web, address) {
	if (!isIP(address)) throw new Error("IP de conexión inválida.");
	const sockets = new Set();
	const track = (socket) => {
		sockets.add(socket);
		socket.once("close", () => sockets.delete(socket));
		socket.on("error", () => socket.destroy());
		return socket;
	};
	const sameHost = (value) =>
		value.replace(/^\[|\]$/g, "").toLowerCase() === web.host;
	const server = http.createServer((req, res) => {
		let url;
		try {
			url = new URL(req.url);
		} catch {
			res.writeHead(400).end();
			return;
		}
		if (
			web.tls ||
			url.protocol !== "http:" ||
			!sameHost(url.hostname) ||
			Number(url.port || 80) !== web.port ||
			url.username ||
			url.password
		) {
			res.writeHead(403).end();
			return;
		}
		const upstream = http.request(
			{
				host: address,
				port: web.port,
				method: req.method,
				path: url.pathname + url.search,
				headers: {
					...req.headers,
					host: `${web.host}:${web.port}`,
					connection: "close",
				},
				agent: false,
				timeout: 10000,
			},
			(response) => {
				res.writeHead(response.statusCode, response.headers);
				response.pipe(res);
			},
		);
		upstream.on("socket", track);
		upstream.on("timeout", () => upstream.destroy());
		upstream.on("error", () => {
			if (!res.headersSent) res.writeHead(502);
			res.end();
		});
		req.on("aborted", () => upstream.destroy());
		req.pipe(upstream);
	});
	server.on("connection", track);
	server.on("connect", (req, client, head) => {
		if (!web.tls || req.url !== `${web.host}:${web.port}`) {
			client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
			return;
		}
		const upstream = track(net.connect({ host: address, port: web.port }));
		upstream.setTimeout(10000, () => upstream.destroy());
		upstream.once("connect", () => {
			client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			if (head.length) upstream.write(head);
			client.pipe(upstream);
			upstream.pipe(client);
		});
		upstream.once("error", () => client.destroy());
		upstream.once("close", () => client.destroy());
		client.once("close", () => upstream.destroy());
	});
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});
	return {
		url: `http://127.0.0.1:${server.address().port}`,
		close: async () => {
			for (const socket of sockets) socket.destroy();
			await new Promise((resolve) => server.close(resolve));
		},
	};
}
export function runTool(bin, args, timeoutMs, cwd, spawnTool = spawn) {
	return new Promise((resolve) => {
		let stdout = "",
			stderr = "",
			bytes = 0,
			error = "",
			settled = false;
		const outputDecoder = new StringDecoder("utf8"),
			errorDecoder = new StringDecoder("utf8");
		const child = spawnTool(bin, args, {
			shell: false,
			detached: true,
			cwd,
			env: {
				...Object.fromEntries(
					Object.entries(process.env).filter(
						([key]) => !key.startsWith("TRIVY_"),
					),
				),
				LC_ALL: "C",
				NO_COLOR: "1",
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		const kill = (signal = "SIGKILL") => {
			try {
				process.kill(-child.pid, signal);
			} catch {
				child.kill(signal);
			}
		};
		const timer = setTimeout(() => {
			error =
				"Tiempo agotado: salida parcial; no confirma ausencia de vulnerabilidades.";
			kill();
		}, timeoutMs);
		// Nikto writes JSON only on close. Ask it to finish before the hard deadline.
		const finishTimer =
			bin === "nikto"
				? setTimeout(
						() => {
							error =
								"Tiempo agotado: se solicitó el cierre de Nikto; resultado parcial.";
							kill("SIGINT");
						},
						Math.max(1, timeoutMs - 5000),
					)
				: undefined;
		const disconnected = () => {
			kill();
			process.exitCode = 1;
		};
		process.once("SIGHUP", disconnected);
		process.once("SIGTERM", disconnected);
		const done = (code) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			clearTimeout(finishTimer);
			process.removeListener("SIGHUP", disconnected);
			process.removeListener("SIGTERM", disconnected);
			resolve({
				stdout: stdout + outputDecoder.end(),
				stderr: stderr + errorDecoder.end(),
				code,
				error,
			});
		};
		child.on("error", (e) => {
			error =
				e.code === "ENOENT"
					? `${bin} no está instalado o no está en PATH.`
					: e.message;
			done(null);
		});
		child.stdout.on("data", (chunk) => {
			bytes += chunk.length;
			if (bytes > LIMIT) {
				error = "La salida supera 2 MB; resultado parcial.";
				kill();
			} else stdout += outputDecoder.write(chunk);
		});
		child.stderr.on("data", (chunk) => {
			stderr = (stderr + errorDecoder.write(chunk)).slice(-8000);
		});
		child.on("close", (code) => done(code));
	});
}
export async function localCve(endpoint, timeoutMs) {
	const response = await fetch(`http://127.0.0.1:5000/api/${endpoint}`, {
		signal: AbortSignal.timeout(timeoutMs),
		redirect: "error",
	});
	if (!response.ok)
		throw new Error(
			`cve-search local respondió HTTP ${response.status}. Comprueba la API en Kali (127.0.0.1:5000).`,
		);
	const reader = response.body.getReader();
	let bytes = 0;
	const chunks = [];
	try {
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			bytes += value.byteLength;
			if (bytes > LIMIT) {
				await reader.cancel();
				throw new Error(
					"Consulta CVE demasiado extensa (2 MB). Busca un CVE concreto.",
				);
			}
			chunks.push(Buffer.from(value));
		}
	} finally {
		reader.releaseLock();
	}
	return Buffer.concat(chunks).toString("utf8");
}
export async function executeAnalysis(q, runner = runTool, pinnedAddress) {
	if (q.tool === "cve") {
		if (
			!Number.isInteger(q.timeoutSeconds) ||
			q.timeoutSeconds < 5 ||
			q.timeoutSeconds > 180
		)
			throw new Error("Timeout inválido.");
		if (q.cve && !/^CVE-\d{4}-\d{4,}$/.test(q.cve))
			throw new Error("CVE inválido.");
		if (
			!q.cve &&
			(typeof q.product !== "string" ||
				!q.product.trim() ||
				typeof q.vendor !== "string" ||
				!q.vendor.trim())
		)
			throw new Error("Proveedor y producto requeridos.");
		return {
			raw: await localCve(
				q.cve
					? `cve/${q.cve}`
					: `search/${encodeURIComponent(q.vendor)}/${encodeURIComponent(q.product)}`,
				q.timeoutSeconds * 1000,
			),
			stdout: "",
			stderr: "",
			code: 0,
			error: "",
			database:
				"Base local de cve-search; revisar dbInfo para su fecha. La búsqueda por producto requiere revisar manualmente versión y condiciones.",
		};
	}
	const dir = await mkdtemp(path.join(os.tmpdir(), "one-two-three-analysis-"));
	let proxy;
	try {
		// 2.6 appends .json to the output prefix; older Nikto writes the exact name.
		const report = path.join(dir, "report.json");
		const [bin, args] = toolArguments(q, report);
		if (q.tool === "nikto") {
			const web = parseNiktoTarget(q);
			if (!isIP(web.host)) {
				if (!pinnedAddress)
					throw new Error(
						"El dominio debe resolverse y autorizarse en Kali antes de ejecutar Nikto.",
					);
				proxy = await niktoProxy(web, pinnedAddress);
				args.push("-useproxy", proxy.url);
			}
		}
		const result = await runner(bin, args, q.timeoutSeconds * 1000, dir);
		if (q.tool === "nikto") {
			const diagnostic = `${result.stdout}\n${result.stderr}`;
			if (/maximum execution time|Scan terminated:/i.test(diagnostic))
				result.error ||=
					"Nikto terminó antes de completar las pruebas; reporte parcial.";
			if (/\[FAIL\]|Unable to connect|\+ ERROR:/i.test(diagnostic))
				result.error ||=
					"Nikto informó un fallo; revisa el diagnóstico. El resultado no es concluyente.";
		}
		let raw = result.stdout;
		let reportAvailable = true;
		if (q.tool === "nikto" || q.tool === "testssl") {
			try {
				let reportPath = report;
				if (q.tool === "nikto") {
					try {
						await stat(`${report}.json`);
						reportPath = `${report}.json`;
					} catch (e) {
						if (e.code !== "ENOENT") throw e;
					}
				}
				const info = await stat(reportPath);
				if (info.size > LIMIT) throw new Error("Reporte mayor de 2 MB.");
				const content = await readFile(reportPath, "utf8");
				if (!content.trim())
					throw new Error(
						"El reporte está vacío; la herramienta no completó su cierre.",
					);
				raw = content;
				if (q.tool === "nikto") {
					// Operational failures are reported as JSON items even with exit code zero.
					try {
						const json = JSON.parse(raw);
						const rows = Array.isArray(json) ? json : [json];
						if (!rows.length)
							result.error ||=
								"Nikto no reportó ningún host analizado; resultado no concluyente.";
						if (
							rows.some(
								(row) =>
									Array.isArray(row?.vulnerabilities) &&
									row.vulnerabilities.some((item) => item.id === "FAIL"),
							)
						)
							result.error ||=
								"Nikto reportó un fallo al analizar el host; revisa la evidencia y el diagnóstico.";
					} catch {
						/* The server validates the JSON and preserves malformed reports. */
					}
				}
			} catch (e) {
				reportAvailable = false;
				const detail =
					e.code === "ENOENT"
						? `${bin} no generó el reporte JSON.`
						: `No se pudo leer el reporte JSON: ${e.message}`;
				const diagnostic = [result.stderr, result.stdout]
					.filter(Boolean)
					.join("\n")
					.slice(-3000);
				result.error = [
					result.error,
					result.code !== 0
						? `La herramienta terminó con código ${result.code ?? "desconocido"}.`
						: "",
					detail,
					diagnostic,
				]
					.filter(Boolean)
					.join("\n");
			}
		}
		return {
			...result,
			stdout: result.stdout.slice(-8000),
			raw,
			reportAvailable,
			pinnedAddress,
			database:
				"Datos instalados en Kali; consultar disponibilidad y fecha antes de interpretar coincidencias.",
		};
	} finally {
		await proxy?.close();
		await rm(dir, { recursive: true, force: true });
	}
}
export async function inspectAnalysisTools() {
	const result = [];
	for (const [tool, bin, args] of [
		["searchsploit", "searchsploit", ["-h"]],
		["nikto", "nikto", ["-Version"]],
		["testssl", "testssl", ["--version"]],
		["trivy", "trivy", ["--version"]],
	]) {
		const r = await runTool(bin, args, 5000, os.tmpdir());
		let database =
			"Fecha de base no disponible; las bases no se actualizan automáticamente.";
		if (tool === "searchsploit")
			try {
				database = `Archivo exploitdb modificado: ${(await stat("/usr/share/exploitdb/files_exploits.csv")).mtime.toISOString()} (no garantiza actualidad de todos los registros).`;
			} catch {
				/* package may use a different path */
			}
		result.push({
			tool,
			available: r.code === 0 && !r.error,
			detail: (r.error || r.stdout || r.stderr).slice(0, 1500),
			database,
		});
	}
	try {
		result.push({
			tool: "cve",
			available: true,
			detail: "API local disponible en 127.0.0.1:5000",
			database: (await localCve("dbInfo", 5000)).slice(0, 1500),
		});
	} catch (e) {
		result.push({
			tool: "cve",
			available: false,
			detail: e.message,
			database:
				"Configura y carga cve-search local; no se consulta una API pública.",
		});
	}
	return result;
}
if (!process.argv[1] || process.argv[1].endsWith("remote-analysis.mjs")) {
	try {
		let input = "";
		for await (const chunk of process.stdin) {
			input += chunk;
			if (input.length > 15000) throw new Error("Solicitud demasiado extensa.");
		}
		const req = JSON.parse(input);
		console.log(
			JSON.stringify(
				req.operation === "inspect"
					? await inspectAnalysisTools()
					: req.operation === "run"
						? await executeAnalysis(req.query, runTool, req.pinnedAddress)
						: (() => {
								throw new Error("Operación inválida.");
							})(),
			),
		);
	} catch (e) {
		console.error(e.message);
		process.exitCode = 1;
	}
}
