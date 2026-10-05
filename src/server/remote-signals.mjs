import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import tls from "node:tls";

let input = "";
for await (const chunk of process.stdin) {
	input += chunk;
	if (input.length > 30000) throw new Error("Solicitud demasiado extensa.");
}
try {
	const request = JSON.parse(input);
	if (
		!Number.isInteger(request.timeoutMs) ||
		request.timeoutMs < 1 ||
		request.timeoutMs > 60000
	)
		throw new Error("Timeout inválido.");
	const validName = (name) =>
		typeof name === "string" &&
		name.length <= 253 &&
		/^[a-z0-9.-]+$/i.test(name);
	const resolver = new Resolver({
		timeout: Math.min(3000, request.timeoutMs),
		tries: 1,
	});
	const timer = setTimeout(() => {
		resolver.cancel();
	}, request.timeoutMs);
	try {
		if (request.operation === "dns") {
			if (!validName(request.domain)) throw new Error("Dominio inválido.");
			const rows = await Promise.all(
				["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"].map(async (type) => {
					try {
						const values = await resolver.resolve(request.domain, type);
						return { type, values: Array.isArray(values) ? values : [values] };
					} catch (error) {
						return { type, values: [], error: error.code ?? "ERROR" };
					}
				}),
			);
			console.log(JSON.stringify({ rows, resolvers: resolver.getServers() }));
		} else if (request.operation === "resolve") {
			if (
				!Array.isArray(request.names) ||
				request.names.length > 64 ||
				!request.names.every(validName)
			)
				throw new Error("Lista DNS inválida.");
			const entries = await Promise.all(
				request.names.map(async (name) => [
					name,
					await resolver.resolve4(name),
				]),
			);
			console.log(JSON.stringify(Object.fromEntries(entries)));
		} else if (request.operation === "tls") {
			if (
				!validName(request.domain) ||
				isIP(request.address) !== 4 ||
				!Number.isInteger(request.port) ||
				request.port < 1 ||
				request.port > 65535
			)
				throw new Error("Destino TLS inválido.");
			const result = await new Promise((resolve, reject) => {
				const socket = tls.connect({
					host: request.address,
					port: request.port,
					servername: request.domain,
					rejectUnauthorized: false,
				});
				const deadline = setTimeout(
					() => socket.destroy(new Error("La lectura TLS agotó su tiempo.")),
					request.timeoutMs,
				);
				socket.once("error", reject);
				socket.once("close", () => clearTimeout(deadline));
				socket.once("secureConnect", () => {
					const cert = socket.getPeerCertificate();
					if (!cert.fingerprint256) {
						socket.destroy();
						reject(new Error("El servicio no presentó certificado."));
						return;
					}
					resolve({
						address: request.address,
						subject: cert.subject?.CN ?? "",
						issuer: cert.issuer?.CN ?? "",
						san: cert.subjectaltname ?? "",
						validFrom: cert.valid_from,
						validTo: cert.valid_to,
						fingerprint: cert.fingerprint256,
						protocol: socket.getProtocol(),
						authorized: socket.authorized,
						authorizationError: String(socket.authorizationError ?? ""),
						hostnameError:
							tls.checkServerIdentity(request.domain, cert)?.message ?? "",
					});
					socket.destroy();
				});
			});
			console.log(JSON.stringify(result));
		} else throw new Error("Operación no compatible.");
	} finally {
		clearTimeout(timer);
		resolver.cancel();
	}
} catch (error) {
	console.error(
		error instanceof Error ? error.message : "Falló el reconocimiento en Kali.",
	);
	process.exitCode = 1;
}
