export function parseNiktoTarget(q) {
	const input = q.target.trim();
	if (
		!input ||
		/\s/.test(input) ||
		[...input].some((char) => char.charCodeAt(0) < 32)
	)
		throw new Error("Escribe una IP, dominio o URL HTTP/HTTPS válida.");
	const explicit = /^[a-z][a-z\d+.-]*:\/\//i.test(input);
	if (!explicit && /[/?#@]/.test(input))
		throw new Error("Usa una URL HTTP/HTTPS completa o un dominio sin rutas.");
	const rawHost =
		!explicit && input.includes(":") && !input.startsWith("[")
			? `[${input}]`
			: input;
	let url;
	try {
		url = new URL(
			explicit ? input : `${q.tls ? "https" : "http"}://${rawHost}:${q.port}`,
		);
	} catch {
		throw new Error(
			"URL inválida. Usa, por ejemplo, https://webmail.ejemplo.com/webmail/.",
		);
	}
	if (
		!["http:", "https:"].includes(url.protocol) ||
		url.username ||
		url.password ||
		url.search ||
		url.hash
	)
		throw new Error(
			"Nikto admite HTTP/HTTPS sin credenciales, parámetros ni fragmentos.",
		);
	const host = url.hostname
		.replace(/^\[|\]$/g, "")
		.toLowerCase()
		.replace(/\.$/, "");
	if (!host || host.includes("%")) throw new Error("Host de la URL inválido.");
	const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
	const tls = url.protocol === "https:";
	return {
		host,
		port,
		tls,
		root: url.pathname === "/" ? "" : url.pathname,
		url: `${tls ? "https" : "http"}://${host.includes(":") ? `[${host}]` : host}:${port}${url.pathname}`,
	};
}
