import { randomUUID } from "node:crypto";
import type { InstallableTool, KaliInstallView } from "../lib/kali-install.ts";
import { redactText } from "../lib/redaction.ts";

type Launch = (emit: (event: unknown) => void) => Promise<void>;
export class KaliInstallManager {
	private jobs = new Map<string, { owner: string; view: KaliInstallView }>();
	start(owner: string, tools: InstallableTool[], launch: Launch) {
		if ([...this.jobs.values()].some((job) => job.view.state === "running"))
			throw new Error("Ya hay una instalación remota en curso.");
		if (this.jobs.size >= 16)
			this.jobs.delete(this.jobs.keys().next().value as string);
		const view: KaliInstallView = {
			id: randomUUID(),
			tools: [...tools],
			state: "running",
			stage: "Conectando a Kali",
			logs: "",
			error: "",
			truncated: false,
		};
		this.jobs.set(view.id, { owner, view });
		void this.run(view, launch);
		return structuredClone(view);
	}
	get(id: string, owner: string) {
		const job = this.jobs.get(id);
		if (!job || job.owner !== owner)
			throw new Error(
				"La instalación no existe para esta conexión. Su estado no se puede confirmar; vuelve a comprobar Kali.",
			);
		return structuredClone(job.view);
	}
	private async run(view: KaliInstallView, launch: Launch) {
		try {
			await launch((value) => {
				if (!value || typeof value !== "object" || view.state !== "running")
					return;
				const event = value as {
					type?: string;
					data?: unknown;
					code?: unknown;
					error?: unknown;
				};
				if (event.type === "stage" && typeof event.data === "string")
					view.stage = redactText(event.data).slice(0, 200);
				if (event.type === "log" && typeof event.data === "string") {
					const logs = redactText(view.logs + event.data);
					view.truncated ||= logs.length > 100000;
					view.logs = logs.slice(-100000);
				}
				if (event.type === "done" && Number.isInteger(event.code)) {
					view.state = event.code === 0 ? "completed" : "failed";
					view.stage =
						event.code === 0
							? "APT terminó correctamente"
							: "Instalación fallida";
					view.error = redactText(String(event.error ?? "")).slice(0, 2000);
				}
			});
			if (view.state === "running")
				throw new Error("Kali no confirmó la finalización de APT.");
		} catch {
			if (view.state === "running") {
				view.state = "unknown";
				view.stage = "Resultado sin confirmar";
				view.error =
					"Se perdió SSH o se agotó el tiempo. APT puede seguir ejecutándose en Kali. Comprueba su estado antes de reintentar; no se reintenta automáticamente.";
			}
		}
	}
}
