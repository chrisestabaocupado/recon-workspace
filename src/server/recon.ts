import { createServerFn } from "@tanstack/react-start";
import { validateReconQuery } from "../lib/recon.ts";
import { validateScopePlan } from "../lib/scope.ts";
import { kaliVerifications } from "./kali-access.ts";
import { collectRemoteRecon } from "./remote-recon.ts";

let active = false;
let recent: number[] = [];
export const collectPassiveRecon = createServerFn({ method: "POST" })
	.validator((value: unknown) => {
		if (!value || typeof value !== "object" || Array.isArray(value))
			throw new Error("Solicitud inválida.");
		const data = value as Record<string, unknown>;
		return {
			access: kaliVerifications.require(data),
			query: validateReconQuery(data.query),
			plan: validateScopePlan(data.plan),
		};
	})
	.handler(async ({ data }) => {
		const now = Date.now();
		recent = recent.filter((time) => now - time < 60000);
		if (active)
			throw new Error(
				"Ya hay una consulta de reconocimiento en curso. Espera a que termine.",
			);
		if (recent.length >= 6)
			throw new Error(
				"Límite de seis consultas por minuto. Espera antes de volver a consultar.",
			);
		active = true;
		recent.push(now);
		try {
			return await collectRemoteRecon(data.query, data.plan, data.access);
		} finally {
			active = false;
		}
	});
