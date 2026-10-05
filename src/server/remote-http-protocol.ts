export function remoteHttpResponse(value: unknown): Response {
	const data = value as {
		status?: unknown;
		body?: unknown;
		contentType?: unknown;
	} | null;
	if (
		!data ||
		!Number.isInteger(data.status) ||
		Number(data.status) < 200 ||
		Number(data.status) > 599 ||
		typeof data.body !== "string" ||
		data.body.length > 4194304 ||
		!/^(?:[a-z\d+/]{4})*(?:[a-z\d+/]{2}==|[a-z\d+/]{3}=)?$/i.test(data.body) ||
		typeof data.contentType !== "string" ||
		data.contentType.length > 255
	)
		throw new Error("Respuesta HTTPS de Kali inválida.");
	const bytes = Buffer.from(data.body, "base64");
	return new Response(
		[204, 205, 304].includes(Number(data.status)) ? null : bytes,
		{
			status: Number(data.status),
			headers: {
				"content-type": data.contentType,
				"content-length": String(bytes.length),
			},
		},
	);
}
