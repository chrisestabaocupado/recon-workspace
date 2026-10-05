import { CheckCircle2, Circle, Copy, Download } from "lucide-react";
import { useState } from "react";
import type { WorkspaceProject } from "#/lib/storage";
import {
	type CheckAttempt,
	checkKinds,
	checklistMarkdown,
	checkStatuses,
	projectChecklist,
} from "#/lib/test-checklist";
import { Button } from "./ui/button";
import { useWorkspace } from "./WorkspaceProvider";

export function TestChecklist({
	project,
	phase,
}: {
	project: WorkspaceProject;
	phase: CheckAttempt["phase"];
}) {
	const { workspace, execution, recordFailure } = useWorkspace();
	const [previous, setPrevious] = useState(false);
	const [filter, setFilter] = useState("all");
	const [limit, setLimit] = useState(30);
	const [message, setMessage] = useState("");
	const rows = projectChecklist(project, phase, {
		includePrevious: previous,
		pending: workspace.pendingOperations,
		execution,
	});
	const visible = rows.filter(
		(r) =>
			filter === "all" ||
			(filter === "pending"
				? r.status === "pending"
				: filter === "issues"
					? ["failed", "partial", "unknown"].includes(r.status)
					: ["data", "empty", "completed"].includes(r.status)),
	);
	async function copy() {
		try {
			await navigator.clipboard.writeText(
				`# Checklist — ${project.name}\n\n${checklistMarkdown(project, phase, previous, { pending: workspace.pendingOperations, execution })}`,
			);
			setMessage("Checklist e intentos copiados en Markdown.");
		} catch (error) {
			setMessage("No se pudo copiar. Puedes descargar el checklist.");
			recordFailure(project.id, {
				phase,
				stage: "Copiar checklist",
				error:
					error instanceof Error
						? error.message
						: "Portapapeles no disponible.",
			});
		}
	}
	function download() {
		const url = URL.createObjectURL(
			new Blob(
				[
					`# Checklist — ${project.name}\n\n${checklistMarkdown(project, phase, previous, { pending: workspace.pendingOperations, execution })}`,
				],
				{ type: "text/markdown;charset=utf-8" },
			),
		);
		const a = document.createElement("a");
		a.href = url;
		a.download = `checklist-${phase}-${project.id}.md`;
		a.click();
		setTimeout(() => URL.revokeObjectURL(url), 1000);
	}
	return (
		<section
			className="min-w-0 rounded-xl border bg-card p-6"
			aria-label="Checklist de pruebas"
		>
			<div className="flex flex-wrap items-center justify-between gap-3">
				<h2 className="text-base font-semibold">
					Checklist de pruebas ·{" "}
					{phase === "recon" ? "Reconocimiento" : "Enumeración"}
				</h2>
				<div className="flex flex-wrap gap-2">
					<Button
						variant="outline"
						size="sm"
						onClick={() => void copy()}
						disabled={!rows.length}
					>
						<Copy className="size-4" />
						Copiar checklist
					</Button>
					<Button
						variant="outline"
						size="sm"
						onClick={download}
						disabled={!rows.length}
					>
						<Download className="size-4" />
						Descargar checklist
					</Button>
				</div>
			</div>
			<p className="mt-2 text-xs text-muted-foreground">
				El estado corresponde al último intento. Con datos / sin datos describen
				el resultado de la prueba; no confirman presencia o ausencia de
				vulnerabilidades. Pendiente significa sin ejecución registrada.
			</p>
			<p className="mt-2 text-xs text-muted-foreground">
				{previous
					? "Todas las revisiones del plan"
					: project.plan
						? `Revisión actual: r${project.plan.revision}`
						: "Sin plan"}{" "}
				· {rows.filter((r) => r.attempts.length).length} pruebas con intentos ·{" "}
				{rows.filter((r) => r.status === "pending").length} pendientes. Las
				consultas pendientes requieren los permisos y el alcance
				correspondientes antes de ejecutarse.
			</p>
			<div className="mt-4 flex flex-wrap items-center gap-2">
				<fieldset
					className="flex flex-wrap gap-1"
					aria-label="Filtrar checklist"
				>
					{[
						["all", "Todas"],
						["success", "Completadas"],
						["issues", "Fallos y parciales"],
						["pending", "Pendientes"],
					].map(([value, label]) => (
						<Button
							key={value}
							size="sm"
							variant={filter === value ? "secondary" : "ghost"}
							aria-pressed={filter === value}
							onClick={() => {
								setFilter(value);
								setLimit(30);
							}}
						>
							{label}
						</Button>
					))}
				</fieldset>
				<Button
					size="sm"
					variant="outline"
					aria-pressed={previous}
					onClick={() => {
						setPrevious((v) => !v);
						setLimit(30);
					}}
				>
					Incluir revisiones anteriores
				</Button>
			</div>
			{message && (
				<output className="mt-3 block text-sm" aria-live="polite">
					{message}
				</output>
			)}
			<div className="mt-4 overflow-x-auto">
				<table className="data-table w-full text-left text-xs">
					<thead>
						<tr className="border-b text-muted-foreground">
							<th className="p-2">Prueba</th>
							<th className="p-2">Objetivo</th>
							<th className="p-2">Último resultado</th>
							<th className="p-2">Intentos</th>
						</tr>
					</thead>
					<tbody>
						{visible.slice(0, limit).map((row) => (
							<tr key={row.key} className="border-b align-top last:border-0">
								<td className="p-2">
									<div className="flex items-start gap-2">
										{row.attempts.length ? (
											<CheckCircle2
												className="size-4 shrink-0"
												aria-label="Intento registrado"
											/>
										) : (
											<Circle
												className="size-4 shrink-0 text-muted-foreground"
												aria-label="Sin intento registrado"
											/>
										)}
										<span>{checkKinds[row.kind]}</span>
									</div>
									{row.command && (
										<code className="mt-2 block max-w-72 whitespace-pre-wrap break-all text-muted-foreground">
											{row.command}
										</code>
									)}
								</td>
								<td className="max-w-64 break-words p-2">{row.target}</td>
								<td className="p-2">
									<span
										className={`inline-block rounded-md border px-2 py-1 ${["failed", "unknown"].includes(row.status) ? "border-warning-border bg-warning-surface text-warning" : row.status === "partial" ? "border-warning-border bg-warning-surface text-warning" : ["data", "empty", "completed"].includes(row.status) ? "border-success-border bg-success-surface text-success" : "text-muted-foreground"}`}
									>
										{checkStatuses[row.status]}
									</span>
									{row.attempts[0] && (
										<p className="mt-2 text-muted-foreground">
											{new Date(row.attempts[0].date).toLocaleString()} ·{" "}
											{row.attempts[0].scopeRevision
												? `r${row.attempts[0].scopeRevision}`
												: "revisión no registrada"}
										</p>
									)}
									{row.recovered && (
										<p className="mt-2 text-success">
											Reintento resuelto; fallos anteriores conservados.
										</p>
									)}
								</td>
								<td className="min-w-48 p-2">
									{row.attempts.length ? (
										<details>
											<summary className="cursor-pointer">
												Ver {row.attempts.length} intento(s)
											</summary>
											<ol className="mt-3 grid gap-3">
												{row.attempts.map((a) => (
													<li
														key={a.id}
														className="max-w-96 break-words rounded-md border p-2"
													>
														<p className="font-medium">
															{checkStatuses[a.status]} ·{" "}
															{new Date(a.date).toLocaleString()} ·{" "}
															{a.scopeRevision
																? `r${a.scopeRevision}`
																: "sin revisión"}
														</p>
														<p className="mt-2 whitespace-pre-wrap text-muted-foreground">
															{a.detail}
														</p>
														<p className="mt-2 text-muted-foreground">
															ID: {a.id}
														</p>
													</li>
												))}
											</ol>
										</details>
									) : (
										"Sin intentos registrados"
									)}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
			{!visible.length && (
				<p className="mt-4 text-sm text-muted-foreground">
					No hay pruebas para este filtro y revisión. Incluye revisiones
					anteriores para consultar registros antiguos.
				</p>
			)}
			{visible.length > limit && (
				<Button
					className="mt-3"
					variant="outline"
					onClick={() => setLimit((n) => n + 30)}
				>
					Mostrar más pruebas
				</Button>
			)}
			<p className="mt-3 text-xs text-muted-foreground">
				Se reconstruye el historial disponible y se conservan hasta 500
				resultados nuevos por proyecto, además del registro de incidencias. Las
				pruebas no guardadas anteriormente no se pueden reconstruir.
			</p>
		</section>
	);
}
