import { spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { createInterface } from "node:readline";
import { StringDecoder } from "node:string_decoder";

// One fixed executable; NDJSON keeps stdin open for cancellation commands.
const send = (event, callback) =>
	process.stdout.write(`${JSON.stringify(event)}\n`, callback);
const input = createInterface({ input: process.stdin });
const ARTIFACT_LIMIT = 8 * 1024 * 1024;
let child;
let started = false;
let finished = false;
let reason;
let killTimer;
let deadline;
let args = [];
let optionArgs = [];
let xmlStdout = "";
let xmlTooLarge = false;

function signalTree(signal) {
	if (!child?.pid) return;
	if (process.platform === "win32") {
		const killer = spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
			windowsHide: true,
			stdio: "ignore",
		});
		killer.on("error", () => {
			try {
				child.kill("SIGTERM");
			} catch {}
		});
	} else {
		try {
			process.kill(-child.pid, signal);
		} catch (error) {
			if (error.code !== "ESRCH")
				send({
					type: "warning",
					message: `No pude detener el grupo: ${error.message}`,
				});
		}
	}
}
function cancel(cancelReason = "cancelled") {
	if (finished) return;
	reason ??= cancelReason;
	if (child?.pid) {
		signalTree("SIGTERM");
		killTimer ??= setTimeout(() => signalTree("SIGKILL"), 3000);
	}
}
async function reportArtifact() {
	const xmlIndex = optionArgs.lastIndexOf("-oX");
	const allIndex = optionArgs.lastIndexOf("-oA");
	const filename =
		xmlIndex >= 0
			? optionArgs[xmlIndex + 1]
			: allIndex >= 0
				? `${optionArgs[allIndex + 1]}.xml`
				: undefined;
	if (!filename) return;
	try {
		let data;
		if (filename === "-") {
			if (xmlTooLarge)
				throw new Error(
					"El XML supera 8 MB; no se puede descargar íntegro desde esta ejecución.",
				);
			data = xmlStdout;
		} else {
			if (filename.includes("%"))
				throw new Error(
					"La ruta de XML usa una plantilla de fecha. Descarga el archivo directamente del ejecutor.",
				);
			const info = await stat(filename);
			if (!info.isFile() || info.size > ARTIFACT_LIMIT)
				throw new Error(
					"El XML no es un archivo regular o supera 8 MB. Descárgalo directamente del ejecutor.",
				);
			data = await readFile(filename, "utf8");
		}
		if (data) send({ type: "artifact", filename: "nmap-report.xml", data });
	} catch (error) {
		send({ type: "warning", message: error.message });
	}
}
async function complete(code, signal) {
	if (finished) return;
	finished = true;
	clearTimeout(deadline);
	clearTimeout(killTimer);
	// Also stop descendants that ignore TERM after their group leader exits.
	if (reason && process.platform !== "win32") signalTree("SIGKILL");
	if (code === 0 && !reason) await reportArtifact();
	input.close();
	process.stdin.pause();
	send({ type: "exit", code, signal, reason }, () => process.exit(0));
}
function start(payload) {
	if (started) throw new Error("Ya existe una ejecución en este runner.");
	if (
		payload.tool !== "nmap" ||
		!Array.isArray(payload.args) ||
		payload.args.length > 512 ||
		payload.args.some(
			(arg) =>
				typeof arg !== "string" || arg.length > 8192 || arg.includes("\0"),
		) ||
		payload.args.join("").length > 100000
	)
		throw new Error("Solicitud inválida.");
	if (
		!Number.isInteger(payload.timeoutMs) ||
		payload.timeoutMs < 100 ||
		payload.timeoutMs > 86400000
	)
		throw new Error("Timeout inválido.");
	started = true;
	args = payload.args;
	const separator = args.indexOf("--");
	optionArgs = separator < 0 ? args : args.slice(0, separator);
	child = spawn("nmap", args, {
		detached: process.platform !== "win32",
		windowsHide: true,
		stdio: ["ignore", "pipe", "pipe"],
	});
	deadline = setTimeout(() => cancel("timed_out"), payload.timeoutMs);
	child.once("spawn", () => {
		send({ type: "ready", pid: child.pid });
		if (reason) cancel(reason);
	});
	const stdoutDecoder = new StringDecoder("utf8");
	const stderrDecoder = new StringDecoder("utf8");
	child.stdout.on("data", (data) => {
		const text = stdoutDecoder.write(data);
		if (
			optionArgs.some(
				(arg, index) => arg === "-oX" && optionArgs[index + 1] === "-",
			)
		) {
			if (xmlStdout.length + text.length <= ARTIFACT_LIMIT) xmlStdout += text;
			else {
				xmlTooLarge = true;
				xmlStdout = "";
			}
		}
		send({ type: "log", stream: "stdout", data: text });
	});
	child.stderr.on("data", (data) =>
		send({ type: "log", stream: "stderr", data: stderrDecoder.write(data) }),
	);
	child.once("error", (error) =>
		send({ type: "error", message: error.message }),
	);
	child.once("close", (code, signal) => {
		void complete(code, signal);
	});
}
input.on("line", (line) => {
	try {
		if (line.length > 200000) throw new Error("Solicitud demasiado extensa.");
		const payload = JSON.parse(line);
		if (payload.type === "cancel") {
			cancel(payload.reason === "timed_out" ? "timed_out" : "cancelled");
			return;
		}
		if (payload.type !== "start")
			throw new Error("Mensaje de control inválido.");
		start(payload);
	} catch (error) {
		send({ type: "error", message: error.message });
		if (!started) {
			finished = true;
			input.close();
			process.stdin.pause();
			send({ type: "exit", code: 1 }, () => process.exit(1));
		}
	}
});
input.on("close", () => {
	if (!finished) {
		if (started) cancel();
		else process.exit(0);
	}
});
for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"])
	process.on(signal, () => {
		if (started) cancel();
		else process.exit(0);
	});
