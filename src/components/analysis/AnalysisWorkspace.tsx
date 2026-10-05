import { Link, useBlocker } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import {
	type AnalysisData,
	type AnalysisEvidence,
	type AnalysisTool,
	analysisCommand,
	analysisInventory,
	analysisMarkdown,
	analysisQueryIssues,
	analysisQueryWithPort,
	analysisQueryWithTarget,
	analysisQueryWithTls,
	analysisTools,
	appendAnalysis,
	cveIds,
	defaultAnalysisQuery,
	emptyAnalysis,
	type Finding,
	findingPriority,
	parseAnalysisReport,
	reviewStates,
	toolRecommendations,
	validateAnalysisData,
	validateAnalysisQuery,
} from "#/lib/analysis";
import { failuresMarkdown } from "#/lib/operation-history";
import {
	exportWorkspace,
	validateWorkspace,
	type WorkspaceData,
} from "#/lib/storage";
import {
	inspectVulnerabilityTools,
	runVulnerabilityAnalysis,
	type ToolAvailability,
} from "#/server/analysis";
import { OperationHistory } from "../OperationHistory";
import { PlanField } from "../planning/PlanFields";
import { Button } from "../ui/button";
import { Checkbox } from "../ui/checkbox";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "../ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { useWorkspace } from "../WorkspaceProvider";

const panel = "min-w-0 rounded-xl border bg-card p-6 space-y-4";
const selectClass = "w-full rounded-md border bg-background p-2 text-sm";
function download(content: string, name: string) {
	const url = URL.createObjectURL(
		new Blob([content], { type: "text/plain;charset=utf-8" }),
	);
	const a = document.createElement("a");
	a.href = url;
	a.download = name;
	a.click();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function FindingReview({
	finding,
	save,
}: {
	finding: Finding;
	save: (f: Finding) => void;
}) {
	const [status, setStatus] = useState(finding.status),
		[note, setNote] = useState(finding.note),
		[recommendation, setRecommendation] = useState(finding.recommendation),
		[severity, setSeverity] = useState(finding.severity);
	return (
		<details className="rounded-lg border p-4">
			<summary className="cursor-pointer break-words text-sm font-medium">
				{finding.title} · {finding.severity} · {reviewStates[finding.status]}
			</summary>
			<div className="mt-4 grid gap-4">
				<p className="text-xs text-muted-foreground">
					{finding.target}
					{finding.port ? `:${finding.port}` : ""} · {finding.source} ·{" "}
					{new Date(finding.date).toLocaleString()} · evidencia{" "}
					{finding.evidenceId}
				</p>
				<p className="whitespace-pre-wrap break-words text-sm">
					{finding.description || "Revisar la evidencia original."}
				</p>
				<p className="text-sm">
					CVE: {finding.cves.join(", ") || "Sin asociación CVE"}
				</p>
				<label className="grid gap-2 text-xs">
					Estado
					<select
						className={selectClass}
						value={status}
						onChange={(e) => setStatus(e.target.value as Finding["status"])}
					>
						{Object.entries(reviewStates).map(([key, label]) => (
							<option key={key} value={key}>
								{label}
							</option>
						))}
					</select>
				</label>
				<PlanField
					label="Severidad / CVSS (revisable)"
					value={severity}
					onChange={setSeverity}
				/>
				<PlanField
					label="Evidencia de validación y notas"
					value={note}
					onChange={setNote}
					multiline
					hint="Para confirmar, documenta la prueba, condiciones y parches revisados. Un número de versión no basta."
				/>
				<PlanField
					label="Recomendación"
					value={recommendation}
					onChange={setRecommendation}
					multiline
				/>
				<Button
					variant="outline"
					onClick={() =>
						save({ ...finding, status, note, recommendation, severity })
					}
				>
					Guardar revisión
				</Button>
			</div>
		</details>
	);
}
export function AnalysisWorkspace() {
	const {
		workspace,
		setWorkspace,
		hydrated,
		storageError,
		getKaliAccess,
		kaliReady,
		recordFailure,
		beginOperation,
		finishOperation,
		setProjectCreationBlocked,
	} = useWorkspace();
	const latest = useRef(workspace);
	latest.current = workspace;
	const busyRef = useRef(false);
	const [busy, setBusy] = useState(false),
		[error, setError] = useState(""),
		[message, setMessage] = useState("");
	const [query, setQuery] = useState(defaultAnalysisQuery),
		[tools, setTools] = useState<ToolAvailability[]>([]),
		[toolSignature, setToolSignature] = useState("");
	const [tab, setTab] = useState("summary"),
		[filter, setFilter] = useState(""),
		[statusFilter, setStatusFilter] = useState("all");
	const [fullReport, setFullReport] = useState<{
		id: string;
		raw: string;
		stderr: string;
		format: "txt" | "json";
	}>();
	const [manual, setManual] = useState({
		tool: "manual",
		title: "",
		target: "",
		raw: "",
		description: "",
	});
	const blocker = useBlocker({
		shouldBlockFn: () => busyRef.current,
		enableBeforeUnload: () => busyRef.current,
		withResolver: true,
	});
	useEffect(() => {
		setProjectCreationBlocked(busy);
		return () => setProjectCreationBlocked(false);
	}, [busy, setProjectCreationBlocked]);
	useEffect(() => {
		if (!busy && blocker.status === "blocked") blocker.proceed();
	}, [busy, blocker]);
	const project = workspace.projects.find(
		(p) => p.id === workspace.selectedProjectId,
	);
	const data = project?.analysis ?? emptyAnalysis();
	const inventory = project ? analysisInventory(project) : [];
	function commit(id: string, update: (data: AnalysisData) => AnalysisData) {
		const current = latest.current;
		const p = current.projects.find((p) => p.id === id);
		if (!p) throw new Error("El proyecto original ya no existe.");
		const analysis = validateAnalysisData(
			update(p.analysis ?? emptyAnalysis()),
		);
		const next: WorkspaceData = {
			...current,
			projects: current.projects.map((p) =>
				p.id === id ? { ...p, analysis } : p,
			),
		};
		validateWorkspace(next);
		if (JSON.stringify(next).length > 5 * 1024 * 1024)
			throw new Error(
				"El proyecto supera 5 MB. Descarga el reporte y libera evidencias antiguas.",
			);
		latest.current = next;
		setWorkspace((current) => ({
			...current,
			projects: current.projects.map((p) =>
				p.id === id ? { ...p, analysis } : p,
			),
		}));
	}
	function fail(
		e: unknown,
		stage: string,
		projectId = project?.id,
		context: {
			id?: string;
			source?: string;
			target?: string;
			command?: string;
			scopeRevision?: number;
		} = {},
	) {
		const text =
			e instanceof Error ? e.message : "No se pudo completar la operación.";
		setError(text);
		recordFailure(projectId ?? null, {
			phase: "analysis",
			stage,
			error: text,
			...context,
		});
	}
	function selectService(row: (typeof inventory)[number], tool: AnalysisTool) {
		setQuery({
			...defaultAnalysisQuery(),
			tool,
			target: row.target,
			port: row.observed.port,
			product: row.observed.product ?? row.observed.service,
			version: row.observed.version ?? "",
			tls:
				/ssl|tls|https/i.test(row.observed.service) ||
				[443, 8443, 636, 993, 995, 465].includes(row.observed.port),
		});
		setTab("tools");
		setError("");
	}
	async function inspect() {
		if (busyRef.current) return;
		busyRef.current = true;
		setBusy(true);
		setError("");
		try {
			const access = getKaliAccess();
			const result = await inspectVulnerabilityTools({ data: access });
			setTools(result);
			setToolSignature(access.kaliToken);
			setMessage(
				"Disponibilidad comprobada en Kali. No se instalaron ni actualizaron herramientas.",
			);
		} catch (e) {
			fail(e, "Comprobar herramientas");
		} finally {
			busyRef.current = false;
			setBusy(false);
		}
	}
	async function run() {
		if (!project || busyRef.current) return;
		const id = project.id;
		let attempt = "";
		setError("");
		setMessage("");
		try {
			const q = validateAnalysisQuery(query);
			const issues = analysisQueryIssues(q, project.plan);
			if (issues.length) throw new Error(issues.join(" "));
			const access = getKaliAccess();
			busyRef.current = true;
			setBusy(true);
			attempt = beginOperation(id, {
				phase: "analysis",
				stage: "Ejecutar herramienta",
				source: q.tool,
				target: q.target || q.path || q.product,
				error: "Resultado pendiente de confirmar.",
				scopeRevision: project.plan?.revision,
			});
			const result = await runVulnerabilityAnalysis({
				data: { ...access, query: q, plan: project.plan },
			});
			setFullReport({
				id: result.evidence.id,
				raw: result.fullReport,
				stderr: result.stderr,
				format: result.reportFormat,
			});
			commit(id, (current) =>
				appendAnalysis(current, result.evidence, result.findings),
			);
			if (result.evidence.error) {
				fail(new Error(result.evidence.error), "Interpretar reporte", id, {
					id: attempt,
					source: result.evidence.tool,
					target: result.evidence.target,
					command: result.evidence.query,
					scopeRevision: result.evidence.scopeRevision,
				});
			}
			setMessage(
				result.evidence.error && !result.findings.length
					? "Se guardó la salida con incidencias. No se pudo obtener un resultado concluyente; revisa la evidencia y el diagnóstico."
					: `${result.findings.length} candidatas registradas en el proyecto original. ${result.evidence.error ? "Resultado parcial o con incidencias; revisa la evidencia." : "Revisa aplicabilidad y condiciones antes de confirmar."}`,
			);
			setTab(result.evidence.error ? "evidence" : "findings");
		} catch (e) {
			fail(e, "Ejecutar o guardar análisis", id, {
				id: attempt || undefined,
				source: query.tool,
				target: query.target || query.path || query.product || query.cve,
				command: analysisCommand(query),
				scopeRevision: project.plan?.revision,
			});
		} finally {
			if (attempt) finishOperation(attempt);
			busyRef.current = false;
			setBusy(false);
		}
	}
	function importEvidence() {
		if (!project) return;
		try {
			if (!manual.raw.trim())
				throw new Error("Añade evidencia o un reporte JSON.");
			if (manual.raw.length > 60000)
				throw new Error(
					"Importación limitada a 60.000 caracteres; conserva aparte el reporte original.",
				);
			const tool = manual.tool as AnalysisEvidence["tool"];
			const found =
				tool === "manual"
					? [
							{
								title: manual.title.trim() || "Observación manual",
								description: manual.description || manual.raw.slice(0, 4000),
								severity: "Sin clasificar",
								recommendation:
									"Validar condiciones y documentar medidas de corrección.",
								cves: cveIds(manual.raw),
							},
						]
					: parseAnalysisReport(tool, manual.raw);
			const evidence: AnalysisEvidence = {
				id: crypto.randomUUID(),
				tool,
				target: manual.target || "Sin activo asignado",
				query: manual.title || "Importación manual",
				date: new Date().toISOString(),
				raw: manual.raw,
				warnings: [
					"Importación manual; origen y fecha de ejecución deben documentarse en el reporte.",
				],
				error: "",
			};
			commit(project.id, (current) => appendAnalysis(current, evidence, found));
			setMessage("Evidencia importada y candidatas guardadas.");
			setManual({
				tool: "manual",
				title: "",
				target: "",
				raw: "",
				description: "",
			});
			setError("");
			setTab("findings");
		} catch (e) {
			fail(e, "Importar evidencia");
		}
	}
	let queryIssues: string[] = [];
	try {
		queryIssues = analysisQueryIssues(
			validateAnalysisQuery(query),
			project?.plan,
		);
	} catch (e) {
		queryIssues = [e instanceof Error ? e.message : "Completa la consulta."];
	}
	const activeProbe = query.tool === "nikto" || query.tool === "testssl";
	if (!hydrated) return <p>Cargando proyectos…</p>;
	return (
		<div className="grid gap-5">
			<Dialog
				open={blocker.status === "blocked"}
				onOpenChange={(open) => {
					if (!open) blocker.reset?.();
				}}
			>
				<DialogContent>
					<DialogHeader>
						<DialogTitle>Análisis en curso</DialogTitle>
						<DialogDescription>
							La respuesta se guardará antes de continuar. Cada prueba dura
							hasta 180 segundos, más el cierre SSH. Mantén esta página abierta
							para conservar el reporte.
						</DialogDescription>
					</DialogHeader>
					<Button variant="outline" onClick={() => blocker.reset?.()}>
						Permanecer aquí
					</Button>
				</DialogContent>
			</Dialog>
			{storageError && (
				<p
					role="alert"
					className="rounded-lg border border-destructive p-4 text-sm"
				>
					{storageError}
				</p>
			)}
			<div className="flex flex-wrap items-end gap-3">
				<label className="grid min-w-48 gap-2 text-xs">
					Proyecto
					<select
						className={selectClass}
						disabled={busy}
						value={project?.id ?? ""}
						onChange={(e) => {
							setWorkspace((w) => ({
								...w,
								selectedProjectId: e.target.value,
							}));
							setQuery(defaultAnalysisQuery());
							setFullReport(undefined);
							setError("");
							setMessage("");
							setManual({
								tool: "manual",
								title: "",
								target: "",
								raw: "",
								description: "",
							});
						}}
					>
						<option value="" disabled>
							Selecciona proyecto
						</option>
						{workspace.projects.map((p) => (
							<option key={p.id} value={p.id}>
								{p.name}
							</option>
						))}
					</select>
				</label>
				<Button variant="outline" asChild>
					<Link to="/alcance">Revisar alcance</Link>
				</Button>
				<Button
					variant="outline"
					disabled={!project}
					onClick={() => {
						if (project)
							download(
								`${analysisMarkdown(project)}\n\n${failuresMarkdown(project.failures?.filter((f) => f.phase === "analysis") ?? [])}`,
								`analisis-${project.id}.md`,
							);
					}}
				>
					Informe Markdown
				</Button>
				<Button
					variant="outline"
					disabled={!project}
					onClick={() => {
						try {
							download(exportWorkspace(workspace), "workspace.json");
						} catch (e) {
							fail(e, "Exportar proyecto");
						}
					}}
				>
					Exportar JSON
				</Button>
			</div>
			{error && (
				<p
					role="alert"
					className="rounded-lg border border-destructive p-4 text-sm whitespace-pre-wrap"
				>
					{error}
				</p>
			)}
			{message && (
				<output aria-live="polite" className="text-sm">
					{message}
				</output>
			)}
			{busy && (
				<output className="text-sm text-primary" aria-live="polite">
					Trabajando en Kali… La operación conserva el proyecto y la consulta
					originales.
				</output>
			)}
			{fullReport && (
				<div className="flex flex-wrap items-center gap-3 rounded-lg border p-3 text-xs">
					<span>Último reporte completo disponible durante esta sesión.</span>
					<Button
						size="sm"
						variant="outline"
						onClick={() =>
							download(
								fullReport.raw,
								`analisis-${fullReport.id}.${fullReport.format}`,
							)
						}
					>
						Descargar reporte completo
					</Button>
					{fullReport.stderr && (
						<Button
							size="sm"
							variant="outline"
							onClick={() =>
								download(fullReport.stderr, `diagnostico-${fullReport.id}.txt`)
							}
						>
							Descargar diagnóstico
						</Button>
					)}
				</div>
			)}
			{!project ? (
				<div className={panel}>
					<p>Crea o selecciona un proyecto para analizar resultados.</p>
					<Button asChild>
						<Link to="/alcance">Abrir planificación</Link>
					</Button>
				</div>
			) : (
				<Tabs value={tab} onValueChange={setTab}>
					<TabsList className="h-auto flex-wrap">
						<TabsTrigger value="summary">Resumen</TabsTrigger>
						<TabsTrigger value="tools">Herramientas</TabsTrigger>
						<TabsTrigger value="findings">
							Hallazgos ({data.findings.length})
						</TabsTrigger>
						<TabsTrigger value="evidence">
							Evidencias ({data.evidence.length})
						</TabsTrigger>
					</TabsList>
					<TabsContent value="summary" className="mt-3 grid gap-5">
						<div className="grid grid-cols-2 gap-3 md:grid-cols-4">
							{[
								[
									"Activos observados",
									new Set(inventory.map((r) => r.target)).size,
								],
								["Servicios abiertos", inventory.length],
								[
									"Versiones pendientes",
									inventory.filter((r) => !r.observed.version).length,
								],
								[
									"Candidatas",
									data.findings.filter((f) => f.status === "candidate").length,
								],
							].map(([label, n]) => (
								<div key={label} className="rounded-xl border bg-card p-4">
									<p className="text-2xl font-semibold">{n}</p>
									<p className="text-xs text-muted-foreground">{label}</p>
								</div>
							))}
						</div>
						<div className={panel}>
							<h2 className="font-semibold">
								Qué encontramos y cómo abordarlo
							</h2>
							<p className="text-sm text-muted-foreground">
								Se usan las últimas observaciones conservadas por servicio en
								Enumeración. El historial retiene diez ejecuciones; este resumen
								no representa todos los activos evaluados. Las referencias por
								versión son candidatas. Una configuración débil puede existir
								sin CVE.
							</p>
							<p className="text-sm text-muted-foreground">
								Reconocimiento aporta contexto y evidencias en su propia fase.
								Los nombres candidatos aún no enumerados no prueban que exista
								un servicio vulnerable. Para bibliotecas y paquetes internos
								necesitarás un inventario de dependencias o archivos para Trivy.
							</p>
							<PlanField
								label="Filtrar inventario"
								value={filter}
								onChange={setFilter}
							/>
							{!inventory.length && (
								<p className="text-sm">
									Aún no hay servicios abiertos guardados. Ejecuta Nmap o
									importa un reporte en{" "}
									<Link to="/enumeracion" className="underline">
										Enumeración
									</Link>
									.
								</p>
							)}
							{inventory
								.filter((r) =>
									`${r.target} ${r.observed.service} ${r.observed.product} ${r.observed.version}`
										.toLowerCase()
										.includes(filter.toLowerCase()),
								)
								.slice(0, 100)
								.map((row) => (
									<div
										key={`${row.target}:${row.observed.port}/${row.observed.protocol}`}
										className="rounded-lg border p-4 space-y-3"
									>
										<div className="flex flex-wrap justify-between gap-2">
											<h3 className="text-sm font-semibold">
												{row.target}:{row.observed.port}/{row.observed.protocol}{" "}
												· {row.observed.service}
											</h3>
											<span className="text-xs text-muted-foreground">
												{row.observed.product || "Producto sin identificar"}{" "}
												{row.observed.version || "· versión pendiente"}
											</span>
										</div>
										<p className="text-xs text-muted-foreground">
											Observado {new Date(row.date).toLocaleString()} ·
											ejecución {row.runId}
										</p>
										{!row.observed.version && (
											<p className="text-xs">
												Obtener versión y revisar parches antes de asociar CVE.
											</p>
										)}
										<div className="grid gap-2">
											{toolRecommendations(row.observed).map((r) => (
												<div
													key={r.tool}
													className="flex flex-wrap items-center justify-between gap-2"
												>
													<span className="text-xs">{r.reason}</span>
													<Button
														size="sm"
														variant="outline"
														disabled={busy}
														onClick={() => selectService(row, r.tool)}
													>
														{analysisTools[r.tool]}
													</Button>
												</div>
											))}
										</div>
										{!toolRecommendations(row.observed).length && (
											<p className="text-xs">
												Identificar producto y configuración; documentar
												evidencia manual antes de elegir verificaciones.
											</p>
										)}
									</div>
								))}
							{inventory.length > 100 && (
								<p className="text-xs">
									Se muestran hasta 100 servicios. Usa el filtro para localizar
									otros.
								</p>
							)}
						</div>
					</TabsContent>
					<TabsContent value="tools" className="mt-3 grid gap-5">
						<div className={panel}>
							<div className="flex flex-wrap justify-between gap-3">
								<h2 className="font-semibold">Disponibilidad en Kali</h2>
								<Button
									variant="outline"
									disabled={busy || !kaliReady}
									onClick={() => void inspect()}
								>
									Comprobar herramientas
								</Button>
							</div>
							<p className="text-sm text-muted-foreground">
								Las consultas usan datos locales. Tener Internet en Kali permite
								preparar bases por separado; este módulo no hace actualizaciones
								automáticas ni envía el inventario a servicios públicos.
								cve-search debe escuchar en 127.0.0.1:5000 de Kali.
							</p>
							{!kaliReady && (
								<p className="text-sm">
									Configura y verifica Kali en el navbar para consultar o
									ejecutar herramientas. Puedes revisar e importar datos sin
									conexión.
								</p>
							)}
							{tools.map((t) => (
								<details key={t.tool} className="rounded border p-3 text-xs">
									<summary>
										{analysisTools[t.tool as AnalysisTool] ?? t.tool} ·{" "}
										{t.available
											? "Disponible en la última comprobación"
											: "No disponible"}
									</summary>
									<pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap break-all">
										{t.detail}\n{t.database}
									</pre>
								</details>
							))}
							{toolSignature && (
								<p className="text-xs text-muted-foreground">
									La disponibilidad es una instantánea; vuelve a comprobarla
									después de cambiar de Kali o instalar herramientas.
								</p>
							)}
						</div>
						<div className={panel}>
							<h2 className="font-semibold">Consulta o verificación</h2>
							<fieldset disabled={busy} className="grid gap-4">
								<label className="grid gap-2 text-xs">
									Herramienta
									<select
										className={selectClass}
										value={query.tool}
										onChange={(e) =>
											setQuery((q) => ({
												...q,
												tool: e.target.value as AnalysisTool,
											}))
										}
									>
										{Object.entries(analysisTools).map(([key, label]) => (
											<option key={key} value={key}>
												{label}
											</option>
										))}
									</select>
								</label>
								<div className="grid gap-4 sm:grid-cols-2">
									<PlanField
										label={
											query.tool === "nikto"
												? "URL, dominio o IP del objetivo"
												: activeProbe
													? "IP del objetivo"
													: "Activo asociado (opcional)"
										}
										value={query.target}
										onChange={(target) =>
											setQuery((q) => analysisQueryWithTarget(q, target))
										}
										hint={
											query.tool === "nikto"
												? "Ejemplo: https://webmail.imcpbdc.com.ve/webmail/. La URL ajusta protocolo y puerto; el dominio debe estar incluido en el alcance."
												: undefined
										}
									/>
									{query.tool === "trivy" ? (
										<PlanField
											label="Ruta absoluta en Kali"
											value={query.path}
											onChange={(path) => setQuery((q) => ({ ...q, path }))}
											hint="Carpeta local de paquetes, bibliotecas o código. La base Trivy debe estar preparada."
										/>
									) : activeProbe ? (
										<PlanField
											label="Puerto"
											type="number"
											min={1}
											max={65535}
											value={query.port}
											onChange={(port) =>
												setQuery((q) => analysisQueryWithPort(q, Number(port)))
											}
										/>
									) : (
										<>
											<PlanField
												label="Producto"
												value={query.product}
												onChange={(product) =>
													setQuery((q) => ({ ...q, product }))
												}
											/>
											{query.tool === "cve" && (
												<PlanField
													label="Proveedor en CPE"
													value={query.vendor}
													onChange={(vendor) =>
														setQuery((q) => ({ ...q, vendor }))
													}
													hint="Por ejemplo, apache / http_server. Una consulta por CVE no requiere proveedor."
												/>
											)}
											<PlanField
												label="Versión observada"
												value={query.version}
												onChange={(version) =>
													setQuery((q) => ({ ...q, version }))
												}
												hint={
													query.tool === "cve"
														? "Referencia para revisión; la API devuelve CVE del producto, no filtra automáticamente por versión."
														: "Buscar coincidencias; revisar rangos y parches."
												}
											/>
											<PlanField
												label="CVE concreto (opcional)"
												value={query.cve}
												onChange={(cve) => setQuery((q) => ({ ...q, cve }))}
											/>
										</>
									)}
									<PlanField
										label="Timeout (segundos)"
										hint={
											query.tool === "nikto"
												? "Una ejecución corta puede terminar con evidencia parcial. Nikto pausa un segundo por solicitud y necesita tiempo para cerrar el reporte."
												: undefined
										}
										value={query.timeoutSeconds}
										type="number"
										min={5}
										max={180}
										onChange={(timeoutSeconds) =>
											setQuery((q) => ({
												...q,
												timeoutSeconds: Number(timeoutSeconds),
											}))
										}
									/>
								</div>
								{query.tool === "nikto" && (
									<label
										htmlFor="analysis-https"
										className="flex items-center gap-2 text-sm"
									>
										<Checkbox
											id="analysis-https"
											checked={query.tls}
											onCheckedChange={(tls) =>
												setQuery((q) => analysisQueryWithTls(q, tls === true))
											}
										/>
										Usar HTTPS
									</label>
								)}
								{query.tool === "nikto" && (
									<p className="text-sm text-muted-foreground">
										Se prueba {query.tls ? "HTTPS" : "HTTP"} en el destino
										indicado. Con una URL o dominio se conserva Host/SNI y la
										conexión se fija a una IP comprobada desde Kali. No se
										siguen redirecciones; puedes indicar /webmail/ en la URL. Un
										404 también acredita una respuesta HTTP.
										{query.tls && query.port === 80
											? " Estás usando HTTPS en el puerto 80: verifica que el servicio admita TLS ahí."
											: ""}
									</p>
								)}
								<pre className="overflow-auto rounded-lg bg-muted p-3 text-xs whitespace-pre-wrap break-all">
									{analysisCommand(query)}
								</pre>
								{activeProbe && (
									<p className="text-sm text-muted-foreground">
										Esta prueba contacta un destino y puerto desde Kali.
										Requiere permiso específico de la herramienta, plan aprobado
										y ventana vigente. Estos adaptadores no aplican el límite
										Nmap de paquetes/s; Nikto pausa un segundo entre pruebas.
										testssl.sh admite TLS directo; STARTTLS y hosts virtuales se
										revisan con evidencia importada.
									</p>
								)}
								{queryIssues.length > 0 && (
									<ul className="list-disc pl-5 text-xs text-amber-500">
										{queryIssues.map((issue) => (
											<li key={issue}>{issue}</li>
										))}
									</ul>
								)}
								<Button
									disabled={
										!kaliReady ||
										queryIssues.length > 0 ||
										Boolean(storageError)
									}
									onClick={() => void run()}
								>
									{activeProbe
										? "Ejecutar verificación en Kali"
										: "Consultar datos locales en Kali"}
								</Button>
							</fieldset>
						</div>
					</TabsContent>
					<TabsContent value="findings" className="mt-3 grid gap-4">
						<div className={panel}>
							<h2 className="font-semibold">Revisión y prioridad</h2>
							<p className="text-sm text-muted-foreground">
								La severidad describe el impacto; el estado indica la
								validación. Sin coincidencias no significa que el servicio esté
								libre de vulnerabilidades. Las ejecuciones repetidas conservan
								evidencia por intento.
							</p>
							<label className="grid gap-2 text-xs">
								Filtrar por estado
								<select
									className={selectClass}
									value={statusFilter}
									onChange={(e) => setStatusFilter(e.target.value)}
								>
									<option value="all">Todos</option>
									{Object.entries(reviewStates).map(([k, v]) => (
										<option key={k} value={k}>
											{v}
										</option>
									))}
								</select>
							</label>
							{data.findings
								.filter(
									(f) => statusFilter === "all" || f.status === statusFilter,
								)
								.sort(
									(a, b) =>
										findingPriority(b) - findingPriority(a) ||
										b.date.localeCompare(a.date),
								)
								.map((f) => (
									<FindingReview
										key={`${f.id}:${f.status}:${f.note}:${f.severity}`}
										finding={f}
										save={(updated) => {
											try {
												commit(project.id, (d) => ({
													...d,
													findings: d.findings.map((f) =>
														f.id === updated.id ? updated : f,
													),
												}));
												setError("");
												setMessage("Revisión guardada.");
											} catch (e) {
												fail(e, "Guardar revisión");
											}
										}}
									/>
								))}
							{!data.findings.length && (
								<p className="text-sm">
									Sin hallazgos registrados. Consulta una herramienta o importa
									evidencia.
								</p>
							)}
						</div>
					</TabsContent>
					<TabsContent value="evidence" className="mt-3 grid gap-5">
						<div className={panel}>
							<h2 className="font-semibold">
								Importar reporte o documentar evidencia
							</h2>
							<fieldset
								disabled={busy || Boolean(storageError)}
								className="grid gap-4"
							>
								<label className="grid gap-2 text-xs">
									Origen
									<select
										className={selectClass}
										value={manual.tool}
										onChange={(e) =>
											setManual((m) => ({ ...m, tool: e.target.value }))
										}
									>
										<option value="manual">Observación manual</option>
										{Object.entries(analysisTools).map(([k, v]) => (
											<option key={k} value={k}>
												{v} · JSON
											</option>
										))}
									</select>
								</label>
								<PlanField
									label="Título / procedencia y fecha de la prueba"
									value={manual.title}
									onChange={(title) => setManual((m) => ({ ...m, title }))}
								/>
								<PlanField
									label="Activo / servicio o paquete asociado"
									value={manual.target}
									onChange={(target) => setManual((m) => ({ ...m, target }))}
								/>
								<label className="grid gap-2 text-xs">
									Archivo JSON o texto (máximo 60.000 caracteres)
									<input
										type="file"
										accept=".json,.txt,.log,.md"
										onChange={async (e) => {
											const file = e.target.files?.[0];
											e.target.value = "";
											if (!file) return;
											try {
												if (file.size > 60000)
													throw new Error(
														"Archivo demasiado extenso; límite 60 KB.",
													);
												const raw = await file.text();
												setManual((m) => ({
													...m,
													raw,
													title: m.title || file.name,
												}));
											} catch (err) {
												fail(err, "Leer evidencia");
											}
										}}
									/>
								</label>
								<PlanField
									label="Evidencia / JSON original"
									multiline
									value={manual.raw}
									onChange={(raw) => setManual((m) => ({ ...m, raw }))}
								/>
								<Button onClick={importEvidence}>
									Guardar evidencia y candidatas
								</Button>
							</fieldset>
						</div>
						<div className={panel}>
							<h2 className="font-semibold">Evidencia conservada</h2>
							<p className="text-xs text-muted-foreground">
								Hasta 30 evidencias y 500 hallazgos por proyecto. Exporta antes
								de eliminar; eliminar una evidencia también elimina sus
								hallazgos asociados.
							</p>
							{data.evidence.map((e) => (
								<details key={e.id} className="rounded-lg border p-3">
									<summary className="cursor-pointer break-words text-sm">
										{e.tool} · {e.target} · {new Date(e.date).toLocaleString()}{" "}
										{e.error && "· con incidencias"}
									</summary>
									<div className="mt-3 grid gap-3 text-xs">
										<p className="break-all">
											{e.query} · revisión {e.scopeRevision ?? "—"} ·{" "}
											{e.executor
												? JSON.stringify(e.executor)
												: "importación manual"}
										</p>
										{e.warnings.map((w) => (
											<p key={w}>{w}</p>
										))}
										{e.error && <p className="text-destructive">{e.error}</p>}
										<pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-3">
											{e.raw}
										</pre>
										<div className="flex gap-2">
											<Button
												size="sm"
												variant="outline"
												onClick={() => download(e.raw, `evidencia-${e.id}.txt`)}
											>
												Descargar evidencia
											</Button>
											<Button
												size="sm"
												variant="destructive"
												disabled={busy}
												onClick={() => {
													if (
														window.confirm(
															"¿Eliminar esta evidencia y todos sus hallazgos? Exporta primero si necesitas conservarlos.",
														)
													) {
														try {
															commit(project.id, (d) => ({
																...d,
																evidence: d.evidence.filter(
																	(x) => x.id !== e.id,
																),
																findings: d.findings.filter(
																	(f) => f.evidenceId !== e.id,
																),
															}));
														} catch (err) {
															fail(err, "Eliminar evidencia");
														}
													}
												}}
											>
												Eliminar
											</Button>
										</div>
									</div>
								</details>
							))}
							{!data.evidence.length && (
								<p className="text-sm">Sin evidencias registradas.</p>
							)}
						</div>
					</TabsContent>
				</Tabs>
			)}
			<OperationHistory projectId={project?.id} phase="analysis" />
		</div>
	);
}
