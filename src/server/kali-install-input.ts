import {
	missingInstallableTools,
	validateInstallTools,
} from "../lib/kali-install.ts";
import {
	type KaliVerificationStore,
	kaliVerifications,
} from "./kali-access.ts";

export function validateKaliInstallInput(
	value: unknown,
	store: KaliVerificationStore = kaliVerifications,
) {
	const access = store.require(value);
	const request = value as Record<string, unknown>;
	const tools = validateInstallTools(request.tools);
	const missing = missingInstallableTools(store.tools(access));
	if (tools.some((tool) => !missing.includes(tool)))
		throw new Error(
			"Solo se instalan herramientas detectadas como faltantes. Vuelve a verificar Kali.",
		);
	const sudoPassword = request.sudoPassword ?? "";
	if (
		typeof sudoPassword !== "string" ||
		sudoPassword.length > 1024 ||
		/[\r\n\0]/.test(sudoPassword)
	)
		throw new Error("Contraseña sudo inválida.");
	return { access, tools, sudoPassword };
}
