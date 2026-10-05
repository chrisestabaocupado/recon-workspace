// Uploaded code is fixed. URLs and timeout are data on stdin, never shell code.
let text = "";
for await (const chunk of process.stdin) {
	text += chunk;
	if (text.length > 10000)
		throw new Error("Solicitud HTTPS demasiado extensa.");
}
try {
	const request = JSON.parse(text);
	const url = new URL(request.url);
	if (url.protocol !== "https:" || url.username || url.password || url.port)
		throw new Error(
			"Solo se permiten fuentes HTTPS sin credenciales ni puertos personalizados.",
		);
	if (
		!Number.isInteger(request.timeoutMs) ||
		request.timeoutMs < 1 ||
		request.timeoutMs > 60000
	)
		throw new Error("Timeout remoto inválido.");
	const response = await fetch(url, {
		signal: AbortSignal.timeout(request.timeoutMs),
		redirect: "error",
		credentials: "omit",
		headers: {
			Accept: "application/rdap+json, application/json",
			"User-Agent": "one-two-three-recon/1.0",
		},
	});
	const reader = response.body?.getReader();
	const chunks = [];
	let bytes = 0;
	if (reader) {
		try {
			for (;;) {
				const { done, value } = await reader.read();
				if (done) break;
				bytes += value.byteLength;
				if (bytes > 3 * 1024 * 1024) {
					await reader.cancel();
					throw new Error("La respuesta supera 3 MB. Reduce la consulta.");
				}
				chunks.push(Buffer.from(value));
			}
		} finally {
			reader.releaseLock();
		}
	}
	console.log(
		JSON.stringify({
			status: response.status,
			contentType: response.headers.get("content-type") ?? "",
			body: Buffer.concat(chunks).toString("base64"),
		}),
	);
} catch (error) {
	console.error(
		error instanceof Error ? error.message : "Falló HTTPS en Kali.",
	);
	process.exitCode = 1;
}
