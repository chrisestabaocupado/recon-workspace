import { useState } from "react";
import {
	failuresMarkdown,
	type OperationFailure,
} from "#/lib/operation-history";
import { Button } from "./ui/button";
import { useWorkspace } from "./WorkspaceProvider";

export function OperationHistory({
	projectId,
	phase,
}: {
	projectId?: string;
	phase: OperationFailure["phase"];
}) {
	const { workspace, recordFailure } = useWorkspace();
	const [message, setMessage] = useState("");
	const [limit, setLimit] = useState(20);
	const project = workspace.projects.find((p) => p.id === projectId);
	const failures = [...(project?.failures ?? []), ...(workspace.failures ?? [])]
		.filter((f) => f.phase === phase)
		.sort((a, b) => b.lastAt.localeCompare(a.lastAt));
	async function copy() {
		try {
			await navigator.clipboard.writeText(
				`# Registro — ${project?.name ?? "Sin proyecto"}\n\n${failuresMarkdown(failures)}`,
			);
			setMessage("Registro copiado para compartir con tu asistente.");
		} catch (error) {
			setMessage("No se pudo copiar. Puedes descargar el registro.");
			recordFailure(projectId ?? null, {
				phase,
				stage: "Copiar registro",
				error:
					error instanceof Error
						? error.message
						: "Portapapeles no disponible.",
			});
		}
	}
	function download() {
		const url = URL.createObjectURL(
			new Blob([failuresMarkdown(failures)], {
				type: "text/markdown;charset=utf-8",
			}),
		);
		const a = document.createElement("a");
		a.href = url;
		a.download = `incidencias-${projectId ?? "general"}.md`;
		a.click();
		setTimeout(() => URL.revokeObjectURL(url), 1000);
	}
	return (
		<section
			className="min-w-0 rounded-xl border bg-card p-6"
			aria-label="Registro de incidencias"
		>
			<div className="flex flex-wrap items-center justify-between gap-3">
				<h2 className="text-base font-semibold">
					Incidencias e intentos fallidos ({failures.length})
				</h2>
				<div className="flex flex-wrap gap-2">
					<Button
						variant="outline"
						size="sm"
						disabled={!failures.length}
						onClick={() => void copy()}
					>
						Copiar registro
					</Button>
					<Button
						variant="outline"
						size="sm"
						disabled={!failures.length}
						onClick={download}
					>
						Descargar registro
					</Button>
				</div>
			</div>
			<p className="mt-2 text-xs text-muted-foreground">
				Se conservan las últimas 300 incidencias por proyecto y 300 sin proyecto
				en este navegador. Un fallo no confirma ausencia de datos ni una
				vulnerabilidad. Exporta una copia para conservar el historial.
			</p>
			{message && (
				<output className="mt-3 block text-sm" aria-live="polite">
					{message}
				</output>
			)}
			{!failures.length && (
				<p className="mt-4 text-sm text-muted-foreground">
					Sin incidencias registradas.
				</p>
			)}
			<div className="mt-4 grid gap-3">
				{failures.slice(0, limit).map((f) => (
					<details key={f.id} className="min-w-0 rounded-lg border p-3">
						<summary className="cursor-pointer break-words text-sm">
							{f.stage} · {f.source ?? f.target ?? "Operación"} ·{" "}
							{new Date(f.lastAt).toLocaleString()}{" "}
							{f.occurrences > 1 && `· ${f.occurrences} apariciones`}
						</summary>
						<div className="mt-3 grid gap-2 break-words text-xs">
							<p className="whitespace-pre-wrap text-warning">{f.error}</p>
							<p>
								Primera aparición: {f.date} · Plan:{" "}
								{f.scopeRevision
									? `r${f.scopeRevision}`
									: "sin revisión registrada"}
							</p>
							{f.target && <p>Objetivo: {f.target}</p>}
							{f.jobId && <p>Ejecución: {f.jobId}</p>}
							{f.command && (
								<pre className="whitespace-pre-wrap break-all">{f.command}</pre>
							)}
							<p className="text-muted-foreground">ID: {f.id}</p>
						</div>
					</details>
				))}
			</div>
			{failures.length > limit && (
				<Button
					className="mt-3"
					variant="outline"
					onClick={() => setLimit((n) => n + 20)}
				>
					Mostrar más
				</Button>
			)}
		</section>
	);
}
