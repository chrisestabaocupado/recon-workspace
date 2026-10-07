// Shared by the UI and the program sent to Kali. Only the fixed NVD endpoint is used.
export function nvdCpe(value) {
	if (!value) return "";
	if (typeof value !== "string" || value.length > 1000)
		throw new Error("CPE inválido.");
	let cpe = value.trim();
	if (cpe.startsWith("cpe:/")) {
		const parts = cpe.slice(5).split(":");
		// Convert only simple URI bindings; escaped/packed editions need operator review.
		if (parts.length > 7 || parts.some((p) => !/^[a-zA-Z0-9_.-]*$/.test(p)))
			throw new Error("Revisa el CPE y proporciona su formato CPE 2.3.");
		cpe = `cpe:2.3:${Array.from({ length: 11 }, (_, i) => parts[i] || "*").join(":")}`;
	}
	const parts = cpe.split(":");
	if (
		parts.length !== 13 ||
		parts[0] !== "cpe" ||
		parts[1] !== "2.3" ||
		!/[aho]/.test(parts[2]) ||
		parts[2].length !== 1 ||
		parts.slice(3, 6).some((p) => !p || p === "*" || p === "-") ||
		parts.slice(2).some((p) => !/^[a-zA-Z0-9_.*?-]+$/.test(p)) ||
		parts.slice(3, 6).some((p) => /[*?]/.test(p))
	)
		throw new Error(
			"Usa un CPE 2.3 con proveedor, producto y versión concretos.",
		);
	return cpe;
}
export function nvdUrl(query) {
	const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
	url.searchParams.set("resultsPerPage", "100");
	url.searchParams.set("noRejected", "");
	if (query.cve) {
		if (!/^CVE-\d{4}-\d{4,}$/.test(query.cve)) throw new Error("CVE inválido.");
		url.searchParams.set("cveId", query.cve);
	} else if (query.cpe) {
		url.searchParams.set("cpeName", nvdCpe(query.cpe));
		url.searchParams.set("isVulnerable", "");
	} else {
		if (
			typeof query.product !== "string" ||
			!query.product.trim() ||
			query.product.length > 200
		)
			throw new Error("Escribe un producto, CPE o CVE para consultar NVD.");
		url.searchParams.set("keywordSearch", query.product.trim());
	}
	return url.toString();
}
