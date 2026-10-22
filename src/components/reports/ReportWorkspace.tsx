import { Link } from "@tanstack/react-router";
import { Copy, Download, FileText, Printer } from "lucide-react";
import { useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
	buildProjectReport,
	type ProjectReport,
	reportFilename,
	reportMarkdown,
} from "#/lib/report";
import { Alert, AlertDescription } from "../ui/alert";
import { Button } from "../ui/button";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "../ui/select";
import { useWorkspace } from "../WorkspaceProvider";

function withKeys<T>(items: T[]) {
	const occurrences = new Map<string, number>();
	return items.map((item) => {
		const value = JSON.stringify(item);
		const count = occurrences.get(value) ?? 0;
		occurrences.set(value, count + 1);
		return { item, key: `${value}:${count}` };
	});
}

function ReportDocument({ report }: { report: ProjectReport }) {
	return (
		<article
			className="project-report min-w-0 space-y-8 rounded-xl border bg-card p-5 md:p-8"
			aria-label="Informe de reconocimiento y mapeo"
		>
			<header className="space-y-3 border-b pb-6">
				<p className="text-xs uppercase tracking-wider text-muted-foreground">
					Reconocimiento · Mapeo · Inventario
				</p>
				<h2 className="break-words text-2xl font-semibold">{report.title}</h2>
				<p className="break-words text-xs text-muted-foreground">
					Proyecto: {report.projectId} · Generado (UTC): {report.generatedAt}
				</p>
			</header>
			{report.sections.map((section) => (
				<section key={section.title} className="min-w-0 space-y-3">
					<h3 className="break-words text-base font-semibold">
						{section.title}
					</h3>
					{withKeys(section.paragraphs ?? []).map(
						({ item: paragraph, key }) => (
							<p
								key={key}
								className="whitespace-pre-line break-words text-sm leading-relaxed text-muted-foreground"
							>
								{paragraph}
							</p>
						),
					)}
					{section.columns && Boolean(section.rows?.length) && (
						<div className="report-table-container overflow-x-auto rounded-lg border">
							<table className="w-full text-left text-xs">
								<caption className="sr-only">{section.title}</caption>
								<thead className="bg-muted/50">
									<tr>
										{section.columns.map((column) => (
											<th
												scope="col"
												key={column}
												className="p-3 align-top font-medium"
											>
												{column}
											</th>
										))}
									</tr>
								</thead>
								<tbody>
									{withKeys(section.rows ?? []).map(({ item: row, key }) => (
										<tr key={key} className="border-t">
											{section.columns?.map((column, cellIndex) => (
												<td
													key={column}
													className="min-w-24 max-w-sm whitespace-pre-line p-3 align-top wrap-anywhere"
												>
													{row[cellIndex]}
												</td>
											))}
										</tr>
									))}
								</tbody>
							</table>
						</div>
					)}
				</section>
			))}
		</article>
	);
}

export function ReportWorkspace() {
	const { workspace, setWorkspace, hydrated, storageError, execution } =
		useWorkspace();
	const [message, setMessage] = useState("");
	const project = workspace.projects.find(
		(item) => item.id === workspace.selectedProjectId,
	);
	const report = useMemo(
		() =>
			project
				? buildProjectReport(project, new Date().toISOString(), {
						pending: workspace.pendingOperations,
						execution,
					})
				: null,
		[project, workspace.pendingOperations, execution],
	);
	const markdown = useMemo(
		() => (report ? reportMarkdown(report) : ""),
		[report],
	);
	const busy = Boolean(
		project &&
			(workspace.pendingOperations?.some(
				(item) => item.projectId === project.id,
			) ||
				(execution?.projectId === project.id &&
					["starting", "running", "cancelling"].includes(execution.state))),
	);

	function download() {
		if (!project || !report) return;
		const url = URL.createObjectURL(
			new Blob([markdown], { type: "text/markdown;charset=utf-8" }),
		);
		const anchor = document.createElement("a");
		anchor.href = url;
		anchor.download = reportFilename(project.id);
		anchor.click();
		setTimeout(() => URL.revokeObjectURL(url), 1000);
	}
	async function copy() {
		try {
			await navigator.clipboard.writeText(markdown);
			setMessage("Informe Markdown copiado.");
		} catch {
			setMessage("No se pudo copiar. Puedes descargar el informe Markdown.");
		}
	}
	if (!hydrated)
		return (
			<output className="text-sm text-muted-foreground">
				Cargando informes…
			</output>
		);
	return (
		<div className="space-y-6">
			{storageError && (
				<Alert variant="destructive">
					<AlertDescription>
						{storageError} El informe refleja los datos disponibles en memoria.
					</AlertDescription>
				</Alert>
			)}
			{!workspace.projects.length ? (
				<div className="rounded-xl border border-dashed p-10 text-center">
					<FileText className="mx-auto mb-4 size-8 text-muted-foreground" />
					<h2 className="text-lg font-semibold">
						Todavía no hay proyectos para informar
					</h2>
					<p className="my-3 text-sm text-muted-foreground">
						Crea un proyecto y reúne los datos de reconocimiento y mapeo.
					</p>
					<Button asChild>
						<Link to="/alcance">Ir a Alcance y planificación</Link>
					</Button>
				</div>
			) : (
				<>
					<div className="space-y-4 rounded-xl border bg-card p-5">
						<div className="flex flex-wrap items-end justify-between gap-4">
							<div className="grid w-full gap-2 sm:w-80">
								<span id="report-project-label" className="text-xs font-medium">
									Proyecto del informe
								</span>
								<Select
									value={workspace.selectedProjectId ?? ""}
									onValueChange={(id) => {
										setWorkspace((current) => ({
											...current,
											selectedProjectId: id,
										}));
										setMessage("");
									}}
								>
									<SelectTrigger
										aria-labelledby="report-project-label"
										className="w-full"
									>
										<SelectValue placeholder="Selecciona un proyecto" />
									</SelectTrigger>
									<SelectContent>
										{workspace.projects.map((item) => (
											<SelectItem key={item.id} value={item.id}>
												{item.name}
											</SelectItem>
										))}
									</SelectContent>
								</Select>
							</div>
							<div className="flex flex-wrap gap-2">
								<Button
									variant="outline"
									disabled={!report}
									onClick={() => void copy()}
								>
									<Copy className="size-4" />
									Copiar
								</Button>
								<Button variant="outline" disabled={!report} onClick={download}>
									<Download className="size-4" />
									Markdown
								</Button>
								<Button disabled={!report} onClick={() => window.print()}>
									<Printer className="size-4" />
									Imprimir / PDF
								</Button>
							</div>
						</div>
						<p className="text-xs leading-relaxed text-muted-foreground">
							El informe se actualiza con los datos guardados del proyecto, sin
							ejecutar consultas. Para obtener un PDF, elige «Guardar como PDF»
							en el diálogo de impresión del navegador. Incluye evidencias e
							incidencias: revisa los datos sensibles antes de compartir.
						</p>
						{message && (
							<output className="block text-sm" aria-live="polite">
								{message}
							</output>
						)}
					</div>
					{busy && (
						<Alert>
							<AlertDescription>
								Hay operaciones en curso. El informe contiene únicamente
								resultados ya guardados y señala las actividades pendientes de
								confirmar. Espera a que terminen si necesitas una entrega final.
							</AlertDescription>
						</Alert>
					)}
					{report && (
						<>
							<div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
								{[
									["Activos no descartados", report.summary.assets],
									["Hosts observados", report.summary.hosts],
									["Puertos abiertos observados", report.summary.openPorts],
									["Evidencias", report.summary.evidence],
								].map(([label, count]) => (
									<div key={label} className="rounded-xl border bg-card p-4">
										<p className="text-xs text-muted-foreground">{label}</p>
										<p className="mt-2 text-2xl font-semibold">{count}</p>
									</div>
								))}
							</div>
							<ReportDocument report={report} />
							{createPortal(
								<div className="report-print-root">
									<ReportDocument report={report} />
								</div>,
								document.body,
							)}
						</>
					)}
				</>
			)}
		</div>
	);
}
