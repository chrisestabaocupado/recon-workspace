import { createFileRoute, Link } from "@tanstack/react-router";
import {
	Activity,
	ArrowDownToLine,
	ArrowUpFromLine,
	CircleHelp,
	Command,
	FolderKanban,
	LoaderCircle,
	LockKeyhole,
	Network,
	Plus,
	Radar,
	Search,
	Settings2,
	Shield,
	Square,
	Terminal,
	Trash2,
	X,
} from "lucide-react";
import {
	Children,
	cloneElement,
	isValidElement,
	lazy,
	type ReactElement,
	Suspense,
	useEffect,
	useId,
	useRef,
	useState,
} from "react";
import { ExecutionRequirementsNotice } from "#/components/ExecutionRequirementsNotice";
import {
	KaliConnectionButton,
	KaliExecutionCard,
} from "#/components/KaliConnection";
import { OperationHistory } from "#/components/OperationHistory";
import { PhaseMobileNav, PhaseSidebar } from "#/components/PhaseSidebar";
import { TestChecklist } from "#/components/TestChecklist";
import { Alert, AlertDescription, AlertTitle } from "#/components/ui/alert";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "#/components/ui/card";
import { Checkbox } from "#/components/ui/checkbox";
import { Input } from "#/components/ui/input";
import { ScrollArea } from "#/components/ui/scroll-area";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import { Separator } from "#/components/ui/separator";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "#/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "#/components/ui/tabs";
import { Textarea } from "#/components/ui/textarea";
import { useWorkspace } from "#/components/WorkspaceProvider";
import { isActiveJob } from "#/lib/execution";
import {
	buildNmapCommand,
	emptyConfigWithProfile,
	emptyNmapConfig,
	hasNmapTargets,
	type NmapConfig,
	type NmapGroup,
	nmapGroups,
	nmapOptions,
	parseNmapCommand,
	quoteArg,
	tokenizeCommand,
} from "#/lib/nmap";
import { redactText } from "#/lib/redaction";
import {
	mergeObservedHosts,
	parseNmapResults,
	readNmapReport,
} from "#/lib/results";
import { addressRange, scopedCommandIssues } from "#/lib/scope";
import {
	exportWorkspace,
	importWorkspace,
	validateWorkspace,
} from "#/lib/storage";
import { appendCheckHistory, runCheck } from "#/lib/test-checklist";
import { getNmapArtifact } from "#/server/jobs";

const NmapCommandEditor = lazy(() =>
	import("#/components/NmapCommandEditor").then((module) => ({
		default: module.NmapCommandEditor,
	})),
);
export const Route = createFileRoute("/enumeracion")({ component: Workspace });
function Workspace() {
	const {
		workspace,
		recordFailure,
		beginOperation,
		finishOperation,
		setWorkspace,
		setProjectDialogOpen,
		replaceWorkspace,
		getKaliAccess,
		kaliReady,
		hydrated,
		storageError,
		setStorageError,
		execution,
		startingRequest,
		startExecution,
		cancelExecution,
	} = useWorkspace();
	const [config, setConfig] = useState<NmapConfig>(emptyNmapConfig());
	const [command, setCommand] = useState("nmap");
	const [commandError, setCommandError] = useState("");
	const [commandWarning, setCommandWarning] = useState("");
	const [submissionError, setSubmissionError] = useState("");
	const [timeoutSeconds, setTimeoutSeconds] = useState(600);
	const [activeGroup, setActiveGroup] = useState<NmapGroup>("Puertos");
	const [fieldSearch, setFieldSearch] = useState("");
	const [profile, setProfile] = useState("custom");
	const [authorized, setAuthorized] = useState(false);
	const jobId = execution?.id ?? "";
	const jobState = execution?.state ?? "";
	const jobLog = execution?.logs ?? "";
	const jobError = submissionError || execution?.error || "";
	const isStarting = startingRequest;
	const activeJob = execution ? isActiveJob(execution.state) : false;
	const [newTarget, setNewTarget] = useState("");
	const fileInputRef = useRef<HTMLInputElement>(null);
	const reportInputRef = useRef<HTMLInputElement>(null);
	const logRef = useRef<HTMLPreElement>(null);
	const projectsRef = useRef(workspace.projects);
	projectsRef.current = workspace.projects;
	useEffect(() => {
		if (!hydrated) return;
		const selected = projectsRef.current.find(
			(item) => item.id === workspace.selectedProjectId,
		);
		if (!selected) return;
		const next = {
			...emptyNmapConfig(),
			targets: selected.targets.map((target) => target.value),
		};
		setConfig(next);
		setCommand(buildNmapCommand(next));
		setCommandError("");
	}, [workspace.selectedProjectId, hydrated]);
	useEffect(() => {
		if (jobLog && logRef.current)
			logRef.current.scrollTop = logRef.current.scrollHeight;
	}, [jobLog]);
	const project =
		workspace.projects.find(
			(item) => item.id === workspace.selectedProjectId,
		) ?? workspace.projects[0];
	const groupOptions = nmapOptions.filter(
		(option) =>
			option.group === activeGroup &&
			(!fieldSearch ||
				`${option.label} ${option.flags.join(" ")} ${option.description}`
					.toLowerCase()
					.includes(fieldSearch.toLowerCase())),
	);
	const executedProject = workspace.projects.find(
		(item) => item.id === execution?.projectId,
	);
	const currentRun = execution
		? executedProject?.lastRuns?.find((run) => run.id === execution.id)
		: project?.lastRuns?.[0];
	const currentResults = mergeObservedHosts(
		currentRun?.hosts ??
			(execution && !activeJob && !execution.truncated
				? parseNmapResults(jobLog)
				: []),
	);
	let scopeIssues: string[] = [];
	try {
		scopeIssues = scopedCommandIssues(
			tokenizeCommand(command).slice(1),
			project?.plan,
			timeoutSeconds,
		);
	} catch {
		/* The command editor shows syntax errors separately. */
	}
	function updateConfig(next: NmapConfig) {
		setConfig(next);
		try {
			const text = buildNmapCommand(next);
			const validated = parseNmapCommand(text);
			setCommand(text);
			setCommandError("");
			setCommandWarning(
				validated.unknown.length
					? "Opciones avanzadas no reconocidas: se conservarán exactamente; revisa sus valores."
					: "",
			);
		} catch (error) {
			setCommandError(
				error instanceof Error
					? error.message
					: "Revisa los valores del formulario.",
			);
		}
		setProfile("custom");
	}
	function updateTargets(raw: string) {
		const targets = raw
			.split(/[\n,\s]+/)
			.map((item) => item.trim())
			.filter(Boolean);
		updateConfig({ ...config, targets });
	}
	function changeCommand(text: string) {
		setCommand(text);
		try {
			const parsed = parseNmapCommand(text);
			setConfig(parsed);
			setCommandError("");
			setCommandWarning(
				parsed.unknown.length
					? "Opciones avanzadas no reconocidas: se conservarán exactamente; revisa sus valores."
					: "",
			);
			setProfile("custom");
		} catch (error) {
			setCommandError(
				error instanceof Error
					? error.message
					: "No pude interpretar el comando.",
			);
		}
	}
	function updateOption(id: string, value: string | boolean | string[]) {
		const values = { ...config.values };
		if (value === false || value === "") delete values[id];
		else values[id] = value;
		updateConfig({ ...config, values });
	}
	function selectProfile(value: string) {
		setProfile(value);
		if (value === "custom") return;
		updateConfig({
			...emptyConfigWithProfile(value as "discovery" | "quick" | "service"),
			targets: config.targets,
		});
		setProfile(value);
	}
	function addTarget() {
		const value = newTarget.trim();
		if (!value || !project) return;
		if (project.targets.some((item) => item.value === value)) {
			setNewTarget("");
			return;
		}
		const updated = {
			...project,
			targets: [
				...project.targets,
				{ id: crypto.randomUUID(), value, note: "" },
			],
		};
		setWorkspace((current) => ({
			...current,
			projects: current.projects.map((item) =>
				item.id === project.id ? updated : item,
			),
		}));
		updateTargets([...config.targets, value].join("\n"));
		setNewTarget("");
	}
	function removeTarget(id: string) {
		if (!project) return;
		const next = project.targets.filter((item) => item.id !== id);
		setWorkspace((current) => ({
			...current,
			projects: current.projects.map((item) =>
				item.id === project.id ? { ...item, targets: next } : item,
			),
		}));
		updateConfig({
			...config,
			targets: config.targets.filter(
				(target) =>
					target !== project.targets.find((item) => item.id === id)?.value,
			),
		});
	}
	async function runScan() {
		if (!project) {
			setProjectDialogOpen(true);
			return;
		}
		if (commandError) return;
		setSubmissionError("");
		let attemptId: string | undefined;
		try {
			const parsed = parseNmapCommand(command);
			if (!hasNmapTargets(parsed)) {
				recordFailure(project.id, {
					phase: "enumeration",
					stage: "Validar comando",
					command,
					error: "Falta un objetivo u operación de diagnóstico.",
				});
				setCommandError(
					"Agrega un objetivo, archivo de entrada o una operación de diagnóstico.",
				);
				return;
			}
			const argv = tokenizeCommand(command).slice(1);
			const access = getKaliAccess();
			attemptId = beginOperation(project.id, {
				phase: "enumeration",
				stage: "Iniciar Nmap",
				command,
				scopeRevision: project.plan?.revision,
				error: "Inicio pendiente de confirmar.",
			});
			await startExecution({
				args: argv,
				projectId: project.id,
				...access,
				authorized,
				timeoutSeconds,
				plan: project.plan,
			});
		} catch (error) {
			recordFailure(project.id, {
				phase: "enumeration",
				id: attemptId,
				stage: "Iniciar Nmap",
				error:
					error instanceof Error ? error.message : "No se pudo iniciar Nmap.",
				command,
				scopeRevision: project.plan?.revision,
			});
			setSubmissionError(
				error instanceof Error ? error.message : "No se pudo iniciar Nmap.",
			);
		} finally {
			if (attemptId) finishOperation(attemptId);
		}
	}
	async function cancelScan() {
		await cancelExecution();
	}
	function downloadText(filename: string, text: string, type = "text/plain") {
		const url = URL.createObjectURL(new Blob([text], { type }));
		const anchor = document.createElement("a");
		anchor.href = url;
		anchor.download = filename;
		anchor.click();
		URL.revokeObjectURL(url);
	}
	function saveExport() {
		try {
			downloadText(
				"one-two-three-workspace.json",
				exportWorkspace(workspace),
				"application/json",
			);
		} catch (error) {
			recordFailure(project?.id ?? null, {
				phase: "enumeration",
				stage: "Exportar proyectos",
				error: error instanceof Error ? error.message : "No se pudo exportar.",
			});
			setStorageError(
				error instanceof Error ? error.message : "No se pudo exportar.",
			);
		}
	}
	async function importFile(file?: File) {
		if (!file) return;
		try {
			if (file.size > 5 * 1024 * 1024)
				throw new Error("La importación supera 5 MB.");
			const imported = importWorkspace(await file.text());
			replaceWorkspace(imported);
			const selected = imported.projects.find(
				(item) => item.id === imported.selectedProjectId,
			);
			const next = {
				...emptyNmapConfig(),
				targets: selected?.targets.map((target) => target.value) ?? [],
			};
			updateConfig(next);
			setStorageError("");
		} catch (error) {
			recordFailure(project?.id ?? null, {
				phase: "enumeration",
				stage: "Importar proyectos",
				source: file.name,
				error:
					error instanceof Error
						? error.message
						: "No se pudo importar el archivo.",
			});
			setStorageError(
				error instanceof Error
					? error.message
					: "No se pudo importar el archivo.",
			);
		}
		if (fileInputRef.current) fileInputRef.current.value = "";
	}
	function exportJob() {
		if (jobLog) downloadText(`nmap-${jobId || "output"}.txt`, jobLog);
	}
	async function exportXml() {
		try {
			const artifact = await getNmapArtifact({ data: { id: jobId } });
			if (!artifact)
				throw new Error(
					"El XML ya no está disponible en el servidor; el historial compacto continúa guardado.",
				);
			downloadText(`nmap-${jobId}.xml`, artifact.text, "application/xml");
		} catch (error) {
			recordFailure(execution?.projectId ?? project?.id ?? null, {
				phase: "enumeration",
				stage: "Descargar XML",
				error:
					error instanceof Error ? error.message : "No se pudo descargar XML.",
			});
			setSubmissionError(
				error instanceof Error ? error.message : "No se pudo descargar XML.",
			);
		}
	}
	async function importReport(file?: File) {
		if (!file || !project) return;
		try {
			if (file.size > 8 * 1024 * 1024)
				throw new Error("El reporte supera 8 MB.");
			const report = redactText(await file.text());
			const hosts = readNmapReport(report);
			const run = {
				id: crypto.randomUUID(),
				command: "nmap [reporte importado]",
				scopeRevision: project.plan?.revision,
				state: "completed" as const,
				date: new Date().toISOString(),
				excerpt: report.slice(-7000),
				hosts,
			};
			validateWorkspace({
				...workspace,
				projects: [{ ...project, lastRuns: [run] }],
			});
			setWorkspace((current) => ({
				...current,
				projects: current.projects.map((item) =>
					item.id === project.id
						? {
								...item,
								executions: item.executions + 1,
								checkHistory: appendCheckHistory(
									item.checkHistory,
									runCheck(run),
								),
								lastRuns: [run, ...(item.lastRuns ?? [])].slice(0, 10),
							}
						: item,
				),
			}));
			setSubmissionError("");
		} catch (error) {
			recordFailure(project.id, {
				phase: "enumeration",
				stage: "Importar reporte Nmap",
				source: file.name,
				scopeRevision: project.plan?.revision,
				error:
					error instanceof Error
						? error.message
						: "No pude importar el reporte.",
			});
			setSubmissionError(
				error instanceof Error ? error.message : "No pude importar el reporte.",
			);
		}
		if (reportInputRef.current) reportInputRef.current.value = "";
	}
	return (
		<div className="flex h-dvh flex-col overflow-hidden bg-background text-foreground">
			<header className="relative z-30 flex min-h-16 shrink-0 flex-wrap items-center justify-between gap-3 border-b bg-background/95 px-4 py-3 backdrop-blur md:flex-nowrap md:px-7 md:py-0">
				<div className="flex items-center gap-3">
					<div className="flex size-9 items-center justify-center rounded-xl bg-primary text-primary-foreground">
						<Shield className="size-5" />
					</div>
					<div>
						<div className="text-sm font-semibold tracking-tight">
							Enumeración y mapeo
						</div>
						<div className="text-[11px] text-muted-foreground">
							Recon workspace
						</div>
					</div>
					<Separator
						orientation="vertical"
						className="mx-3 hidden h-8 xl:block"
					/>
					<Badge
						variant="outline"
						className="hidden gap-1.5 font-normal text-muted-foreground xl:inline-flex"
					>
						<LockKeyhole className="size-3" /> Datos locales
					</Badge>
				</div>
				<div className="flex flex-wrap items-center gap-2">
					<KaliConnectionButton />
					<Button
						className="hidden lg:inline-flex"
						variant="ghost"
						size="icon"
						title="Ayuda"
					>
						<CircleHelp className="size-4" />
					</Button>
					<Button variant="outline" size="sm" onClick={saveExport}>
						<ArrowDownToLine className="size-4" />
						<span className="hidden sm:inline">Exportar</span>
					</Button>
					<Button
						variant="outline"
						size="icon"
						title="Importar proyecto"
						onClick={() => fileInputRef.current?.click()}
					>
						<ArrowUpFromLine className="size-4" />
					</Button>
					<Button
						variant="outline"
						size="sm"
						disabled={!project}
						title="Importar reporte Nmap"
						onClick={() => reportInputRef.current?.click()}
					>
						<ArrowUpFromLine className="size-4" />
						<span className="hidden lg:inline">Importar reporte Nmap</span>
					</Button>
					<input
						ref={fileInputRef}
						type="file"
						accept="application/json,.json"
						className="hidden"
						onChange={(event) => void importFile(event.target.files?.[0])}
					/>
					<input
						ref={reportInputRef}
						type="file"
						accept=".xml,.nmap,.txt,application/xml,text/plain"
						className="hidden"
						onChange={(event) => void importReport(event.target.files?.[0])}
					/>
				</div>
			</header>
			<ExecutionRequirementsNotice />
			<div className="mx-auto flex min-h-0 w-full max-w-[1600px] flex-1 flex-col md:grid md:grid-cols-[280px_minmax(0,1fr)]">
				<PhaseMobileNav />
				<aside className="hidden min-h-0 min-w-0 overflow-y-auto overscroll-contain border-r bg-sidebar p-4 md:block">
					<PhaseSidebar />
				</aside>
				<main className="workspace-main">
					<div className="workspace-content">
						<div className="mb-7 flex flex-wrap items-end justify-between gap-4">
							<div>
								<div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
									<Link to="/" className="hover:underline">
										Proyectos
									</Link>
									<span>/</span>
									<span>Enumeración</span>
								</div>
								<h1 className="text-2xl font-semibold tracking-tight md:text-[28px]">
									Nueva enumeración
								</h1>
								<p className="mb-0 mt-1 text-sm text-muted-foreground">
									Prepara los parámetros, revisa el comando y ejecuta Nmap.
								</p>
							</div>
							<div className="flex items-center gap-2">
								<Badge variant="secondary" className="gap-1.5">
									<span className="size-1.5 rounded-full bg-muted-foreground" />{" "}
									Nmap module
								</Badge>
								<Badge variant="outline">Kali · SSH</Badge>
							</div>
						</div>
						{storageError && (
							<Alert variant="destructive" className="mb-5">
								<AlertTitle>No se pudo guardar</AlertTitle>
								<AlertDescription>
									{storageError}
									<Button
										className="mt-2"
										size="sm"
										variant="outline"
										onClick={() => replaceWorkspace({ ...workspace })}
									>
										Guardar el estado actual del proyecto
									</Button>
								</AlertDescription>
							</Alert>
						)}
						<div className="mb-5 grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(280px,.8fr)]">
							<Card id="project-card">
								<CardHeader className="pb-3">
									<div className="flex flex-wrap items-center justify-between gap-3">
										<div className="min-w-0 flex-1 basis-52">
											<CardTitle className="flex items-center gap-2 text-base">
												<FolderKanban className="size-4 text-primary" />
												Proyecto y objetivos
											</CardTitle>
											<CardDescription>
												Los destinos que agregues se completan en el comando
												Nmap.
											</CardDescription>
										</div>
										<Select
											value={project?.id ?? ""}
											onValueChange={(value) =>
												setWorkspace((current) => ({
													...current,
													selectedProjectId: value,
												}))
											}
										>
											<SelectTrigger className="w-full sm:w-[190px]">
												<SelectValue placeholder="Selecciona proyecto" />
											</SelectTrigger>
											<SelectContent>
												{workspace.projects.map((item) => (
													<SelectItem key={item.id} value={item.id}>
														{item.name}
													</SelectItem>
												))}
												{!workspace.projects.length && (
													<SelectItem value="empty" disabled>
														Sin proyectos
													</SelectItem>
												)}
											</SelectContent>
										</Select>
									</div>
								</CardHeader>
								<CardContent className="grid gap-4">
									{!project ? (
										<div className="flex min-h-32 flex-col items-center justify-center rounded-xl border border-dashed bg-muted/20 text-center">
											<FolderKanban className="mb-2 size-5 text-muted-foreground" />
											<p className="mb-2 text-sm text-muted-foreground">
												Crea un proyecto para definir su alcance.
											</p>
											<Button
												size="sm"
												variant="outline"
												onClick={() => setProjectDialogOpen(true)}
											>
												Crear proyecto
											</Button>
										</div>
									) : (
										<>
											<div className="grid gap-3 sm:grid-cols-[1fr_1.3fr]">
												<div className="rounded-lg border bg-muted/15 px-3 py-2.5">
													<div className="text-[11px] text-muted-foreground">
														Proyecto
													</div>
													<div className="mt-1 truncate text-sm font-medium">
														{project.name}
													</div>
												</div>
												<div className="rounded-lg border bg-muted/15 px-3 py-2.5">
													<div className="text-[11px] text-muted-foreground">
														{project.plan?.status === "approved"
															? "Alcance aprobado"
															: "Alcance definido · pendiente de aprobación"}
													</div>
													<div className="mt-1 truncate font-mono text-xs">
														{project.scope ||
															"Agrega el alcance en los datos del proyecto"}
													</div>
												</div>
											</div>
											<div className="grid gap-2 sm:grid-cols-[1fr_auto]">
												<Input
													placeholder="IP, dominio o CIDR · 10.0.0.10"
													value={newTarget}
													onChange={(event) => setNewTarget(event.target.value)}
													onKeyDown={(event) => {
														if (event.key === "Enter") {
															event.preventDefault();
															addTarget();
														}
													}}
												/>
												<Button
													variant="secondary"
													onClick={addTarget}
													disabled={!newTarget.trim()}
												>
													<Plus className="mr-2 size-4" />
													Agregar objetivo
												</Button>
											</div>
											<div className="flex flex-wrap gap-2">
												{project.targets.map((target) => (
													<Badge
														key={target.id}
														variant="outline"
														className="gap-2 py-1.5 font-mono"
													>
														<span className="size-1.5 rounded-full bg-primary" />
														{target.value}
														<Button
															variant="ghost"
															size="icon"
															aria-label={`Quitar ${target.value}`}
															className="ml-1 size-4 rounded-full text-muted-foreground hover:text-foreground"
															onClick={() => removeTarget(target.id)}
														>
															<X className="size-3" />
														</Button>
													</Badge>
												))}
												{!project.targets.length && (
													<span className="text-xs text-muted-foreground">
														Aún no hay objetivos guardados.
													</span>
												)}
											</div>
										</>
									)}
								</CardContent>
							</Card>
							<KaliExecutionCard />
						</div>
						<Card id="nmap-card" className="mb-5 overflow-hidden">
							<CardHeader className="border-b bg-muted/15 pb-4">
								<div className="flex flex-wrap items-center justify-between gap-3">
									<div>
										<CardTitle className="flex items-center gap-2 text-base">
											<Settings2 className="size-4 text-primary" />
											Parámetros Nmap
										</CardTitle>
										<CardDescription>
											Los campos y el comando describen la misma configuración.
										</CardDescription>
									</div>
									<Select value={profile} onValueChange={selectProfile}>
										<SelectTrigger className="w-[220px]">
											<SelectValue placeholder="Perfil de escaneo" />
										</SelectTrigger>
										<SelectContent>
											<SelectItem value="custom">Personalizado</SelectItem>
											<SelectItem value="discovery">
												Descubrimiento de hosts
											</SelectItem>
											<SelectItem value="quick">
												Puertos abiertos rápidos
											</SelectItem>
											<SelectItem value="service">
												Identificación de servicios
											</SelectItem>
										</SelectContent>
									</Select>
								</div>
							</CardHeader>
							<CardContent className="p-0">
								<div className="grid lg:grid-cols-[minmax(0,1.05fr)_minmax(360px,.95fr)]">
									<div className="min-w-0 border-b p-6 lg:border-b-0 lg:border-r">
										<div className="mb-3 flex flex-wrap items-center justify-between gap-3">
											<div className="flex min-w-0 items-center gap-2">
												<div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
													<Settings2 className="size-4" />
												</div>
												<div>
													<div className="text-sm font-medium">
														Opciones de escaneo
													</div>
													<div className="text-[11px] text-muted-foreground">
														{nmapOptions.length} opciones con campos ·
														argumentos avanzados disponibles
													</div>
												</div>
											</div>
											<div className="relative w-full sm:w-48">
												<Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
												<Input
													className="h-9 pl-8 text-xs"
													placeholder="Buscar parámetro…"
													value={fieldSearch}
													onChange={(event) =>
														setFieldSearch(event.target.value)
													}
												/>
											</div>
										</div>
										<Tabs
											value={activeGroup}
											onValueChange={(value) =>
												setActiveGroup(value as NmapGroup)
											}
										>
											<ScrollArea className="w-full whitespace-nowrap pb-2">
												<TabsList className="h-auto w-max justify-start gap-1 bg-transparent p-0">
													{nmapGroups.map((group) => (
														<TabsTrigger
															className="h-8 rounded-md border border-transparent px-2.5 text-xs data-[state=active]:border-border data-[state=active]:bg-background"
															key={group}
															value={group}
														>
															{group}
														</TabsTrigger>
													))}
												</TabsList>
											</ScrollArea>
											{nmapGroups.map((group) => (
												<TabsContent key={group} value={group} className="mt-2">
													<ScrollArea className="h-[320px] pr-3">
														<div className="grid gap-2">
															{group === "Puertos" && (
																<FieldLabel label="Puertos o rangos">
																	<Input
																		className="font-mono"
																		placeholder="22,80,443,8000-8100"
																		value={String(config.values.ports ?? "")}
																		onChange={(event) =>
																			updateOption("ports", event.target.value)
																		}
																	/>
																	<span className="text-[11px] text-muted-foreground">
																		Deja vacío para usar los puertos
																		predeterminados de Nmap.
																	</span>
																</FieldLabel>
															)}
															{group === "Descubrimiento" && (
																<FieldLabel
																	label="Objetivos"
																	hint="Se puede usar IP, hostname o CIDR. Separa varios con coma o espacio."
																>
																	<Textarea
																		className="min-h-16 resize-y font-mono text-xs"
																		placeholder="192.168.1.10\n192.168.1.0/24"
																		value={config.targets.join("\n")}
																		onChange={(event) =>
																			updateTargets(event.target.value)
																		}
																	/>
																</FieldLabel>
															)}
															{groupOptions.map((option) => {
																const value = config.values[option.id];
																return (
																	<div
																		key={option.id}
																		className="flex items-start justify-between gap-4 rounded-lg border px-3 py-2.5 transition-colors hover:bg-muted/25"
																	>
																		<div className="min-w-0">
																			<div className="flex flex-wrap items-center gap-2">
																				<span className="text-[13px] font-medium">
																					{option.label}
																				</span>
																				<code className="text-[10px] text-primary">
																					{option.flags.join(" / ")}
																				</code>
																			</div>
																			<p className="mb-0 mt-0.5 text-[11px] leading-relaxed text-muted-foreground">
																				{option.description}
																			</p>
																		</div>
																		{option.optionalValue ? (
																			<div className="flex shrink-0 items-center gap-2">
																				<Checkbox
																					aria-label={`Activar ${option.label}`}
																					checked={
																						value !== undefined &&
																						value !== false
																					}
																					onCheckedChange={(checked) =>
																						updateOption(
																							option.id,
																							checked === true
																								? typeof value === "string"
																									? value
																									: true
																								: false,
																						)
																					}
																				/>
																				<Input
																					aria-label={`${option.label} ${option.value}`}
																					className="h-8 w-[125px] font-mono text-[11px]"
																					placeholder={
																						option.valueHint ?? option.value
																					}
																					value={
																						typeof value === "string"
																							? value
																							: ""
																					}
																					disabled={
																						value === undefined ||
																						value === false
																					}
																					onChange={(event) =>
																						updateOption(
																							option.id,
																							event.target.value,
																						)
																					}
																				/>
																			</div>
																		) : option.value ? (
																			Array.isArray(value) ? (
																				<Textarea
																					aria-label={`${option.label} ${option.value}`}
																					className="min-h-12 w-[145px] shrink-0 resize-y font-mono text-[11px]"
																					placeholder={`Un valor por línea`}
																					value={value.join("\n")}
																					onChange={(event) =>
																						updateOption(
																							option.id,
																							event.target.value.split("\n"),
																						)
																					}
																				/>
																			) : (
																				<Input
																					aria-label={`${option.label} ${option.value}`}
																					className="h-8 w-[145px] shrink-0 font-mono text-[11px]"
																					placeholder={
																						option.valueHint ?? option.value
																					}
																					value={
																						typeof value === "string"
																							? value
																							: ""
																					}
																					onChange={(event) =>
																						updateOption(
																							option.id,
																							event.target.value,
																						)
																					}
																				/>
																			)
																		) : (
																			<Checkbox
																				className="mt-1 shrink-0"
																				checked={value === true}
																				onCheckedChange={(checked) =>
																					updateOption(
																						option.id,
																						checked === true,
																					)
																				}
																			/>
																		)}
																	</div>
																);
															})}
															{!groupOptions.length &&
																group !== "Descubrimiento" && (
																	<p className="py-8 text-center text-xs text-muted-foreground">
																		No hay parámetros que coincidan.
																	</p>
																)}
														</div>
													</ScrollArea>
												</TabsContent>
											))}
										</Tabs>
										<Separator className="my-3" />
										<FieldLabel
											label="Argumentos avanzados sin mapear"
											hint="Se preservan en el comando; Nmap valida las opciones no catalogadas."
										>
											<Input
												className="font-mono text-xs"
												placeholder="--opcion-adicional valor"
												value={config.unknown.map(quoteArg).join(" ")}
												onChange={(event) => {
													try {
														updateConfig({
															...config,
															unknown: event.target.value
																? tokenizeCommand(event.target.value)
																: [],
														});
													} catch (error) {
														setCommandError(
															error instanceof Error
																? error.message
																: "Revisa las comillas de los argumentos.",
														);
													}
												}}
											/>
										</FieldLabel>
										<Button
											className="mt-3"
											size="sm"
											variant="outline"
											onClick={() => updateOption("output-xml", "-")}
										>
											<ArrowDownToLine className="mr-2 size-3.5" />
											Capturar XML para el inventario
										</Button>
									</div>
									<div className="flex min-w-0 flex-col bg-muted/10">
										<div className="flex items-center justify-between border-b px-6 py-3">
											<div className="flex items-center gap-2">
												<Terminal className="size-4 text-primary" />
												<div>
													<div className="text-sm font-medium">
														Comando de terminal
													</div>
													<div className="text-[11px] text-muted-foreground">
														Argumentos POSIX · ⌃Espacio completa
													</div>
												</div>
											</div>
											<Button
												variant="ghost"
												size="icon"
												title="Restablecer opciones"
												onClick={() => updateConfig(emptyNmapConfig())}
											>
												<Trash2 className="size-4" />
											</Button>
										</div>
										<div className="min-h-[180px] flex-1 p-1">
											<Suspense
												fallback={
													<div className="p-4 font-mono text-xs text-muted-foreground">
														Preparando editor…
													</div>
												}
											>
												<NmapCommandEditor
													value={command}
													onChange={changeCommand}
													targetSuggestions={project?.targets.map(
														(target) => target.value,
													)}
												/>
											</Suspense>
										</div>
										<div className="flex flex-wrap items-center justify-between gap-2 border-t px-6 py-3">
											<div className="flex items-center gap-2 text-[11px] text-muted-foreground">
												<Command className="size-3.5" />
												Se ejecuta con argumentos separados, sin shell
											</div>
											<Button
												variant="outline"
												size="sm"
												onClick={() => navigator.clipboard.writeText(command)}
											>
												<Command className="mr-2 size-3.5" />
												Copiar comando
											</Button>
										</div>
									</div>
								</div>
							</CardContent>
						</Card>
						<div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border bg-card px-6 py-3.5">
							<label
								htmlFor="authorized-scope"
								className="flex max-w-2xl cursor-pointer items-start gap-3"
							>
								<Checkbox
									id="authorized-scope"
									className="mt-0.5"
									checked={authorized}
									onCheckedChange={(checked) => setAuthorized(checked === true)}
								/>
								<span className="text-xs leading-relaxed text-muted-foreground">
									Confirmo que tengo autorización para evaluar los objetivos
									incluidos en este comando y que pertenecen al alcance del
									proyecto.
									{config.targets.some((target) => !addressRange(target)) && (
										<span className="mt-1 block">
											Los nombres DNS se resolverán en el ejecutor; el trabajo
											mostrará la IP fijada en su comando efectivo.
										</span>
									)}
								</span>
							</label>
							<FieldLabel label="Límite de ejecución (segundos)">
								<Input
									type="number"
									min={5}
									max={86400}
									className="w-32"
									value={timeoutSeconds}
									onChange={(event) =>
										setTimeoutSeconds(Number(event.target.value))
									}
								/>
							</FieldLabel>
							<Button
								onClick={() => void runScan()}
								disabled={
									isStarting ||
									activeJob ||
									Boolean(commandError) ||
									scopeIssues.length > 0 ||
									!authorized ||
									!project ||
									!hasNmapTargets(config) ||
									!Number.isInteger(timeoutSeconds) ||
									timeoutSeconds < 5 ||
									timeoutSeconds > 86400 ||
									!kaliReady
								}
								className="min-w-44"
							>
								{isStarting ? (
									<LoaderCircle className="mr-2 size-4 animate-spin" />
								) : (
									<Radar className="mr-2 size-4" />
								)}
								{isStarting ? "Iniciando…" : "Iniciar enumeración"}
							</Button>
						</div>
						{commandWarning && (
							<Alert className="mb-5">
								<AlertTitle>Argumentos avanzados preservados</AlertTitle>
								<AlertDescription>{commandWarning}</AlertDescription>
							</Alert>
						)}
						{commandError && (
							<Alert variant="destructive" className="mb-5">
								<AlertTitle>Revisa el comando</AlertTitle>
								<AlertDescription className="font-mono text-xs">
									{commandError}
								</AlertDescription>
							</Alert>
						)}
						{project && scopeIssues.length > 0 && (
							<Alert className="mb-5">
								<AlertTitle>Revisa el alcance antes de ejecutar</AlertTitle>
								<AlertDescription className="grid gap-2">
									<ul className="list-disc space-y-1 pl-4 text-xs">
										{scopeIssues.map((issue) => (
											<li key={issue}>{issue}</li>
										))}
									</ul>
									<div className="flex flex-wrap gap-2">
										<Button variant="outline" size="sm" asChild>
											<Link to="/alcance">Abrir Alcance y planificación</Link>
										</Button>
										{project.plan && (
											<Button
												variant="outline"
												size="sm"
												disabled={Boolean(commandError)}
												onClick={() => {
													const plan = project.plan;
													if (!plan) return;
													const values = {
														...config.values,
														"max-rate": String(plan.maxRate),
													};
													if (plan.allowedPorts !== "1-65535")
														Object.assign(values, {
															ports: plan.allowedPorts,
															"skip-discovery": true,
														});
													updateConfig({ ...config, values });
													setTimeoutSeconds(
														Math.min(timeoutSeconds, plan.maxDurationSeconds),
													);
												}}
											>
												Aplicar límites del plan al comando
											</Button>
										)}
									</div>
								</AlertDescription>
							</Alert>
						)}
						{execution?.truncated && (
							<Alert className="mb-5">
								<AlertTitle>La vista del log es parcial</AlertTitle>
								<AlertDescription>
									Se conserva el tramo más reciente hasta 1.500.000 caracteres.
									El log descargado también es parcial; usa el XML para el
									reporte completo cuando esté disponible.
								</AlertDescription>
							</Alert>
						)}
						{jobError && (
							<Alert variant="destructive" className="mb-5">
								<AlertTitle>La ejecución requiere atención</AlertTitle>
								<AlertDescription className="text-xs">
									{jobError}
								</AlertDescription>
							</Alert>
						)}
						{jobId && (
							<Card className="overflow-hidden">
								<CardHeader className="flex flex-row items-center justify-between border-b bg-muted/15 py-3.5">
									<div className="flex items-center gap-3">
										<div
											className={`flex size-8 items-center justify-center rounded-lg ${activeJob ? "bg-warning-surface text-warning" : jobState === "completed" ? "bg-success-surface text-success" : "bg-muted text-muted-foreground"}`}
										>
											{activeJob ? (
												<LoaderCircle className="size-4 animate-spin" />
											) : (
												<Activity className="size-4" />
											)}
										</div>
										<div>
											<CardTitle className="text-sm">
												Salida de ejecución
											</CardTitle>
											<CardDescription className="font-mono text-[10px]">
												{executedProject?.name ?? "Proyecto original"} ·{" "}
												{execution?.executor
													? `${execution.executor.username}@${execution.executor.host}:${execution.executor.port}`
													: execution?.mode}{" "}
												· {jobId}
											</CardDescription>
										</div>
										<Badge
											variant={jobState === "completed" ? "success" : "warning"}
										>
											{jobState || "Preparando"}
										</Badge>
									</div>
									<div className="flex flex-wrap gap-2">
										{activeJob && (
											<Button
												size="sm"
												variant="outline"
												disabled={jobState === "cancelling"}
												onClick={() => void cancelScan()}
											>
												<Square className="mr-2 size-3.5" />
												{jobState === "cancelling"
													? "Confirmando…"
													: "Cancelar"}
											</Button>
										)}
										<Button
											size="sm"
											variant="outline"
											onClick={exportJob}
											disabled={!jobLog}
										>
											<ArrowDownToLine className="mr-2 size-3.5" />
											{execution?.truncated
												? "Descargar log parcial"
												: "Descargar log"}
										</Button>
										{execution?.artifactAvailable && (
											<Button
												size="sm"
												variant="outline"
												onClick={() => void exportXml()}
											>
												Descargar XML
											</Button>
										)}
									</div>
								</CardHeader>
								<CardContent className="p-0">
									<div className="border-b px-6 py-2 font-mono text-xs text-muted-foreground">
										{execution?.command}
										{execution?.scopeRevision && (
											<span className="ml-3 text-muted-foreground">
												Plan · revisión {execution.scopeRevision}
											</span>
										)}
									</div>
									<pre
										ref={logRef}
										className="m-0 max-h-[420px] min-h-28 overflow-auto bg-background px-6 py-4 font-mono text-[11px] leading-relaxed text-foreground"
									>
										{jobLog || (
											<span className="text-muted-foreground">
												Esperando salida de Nmap…
											</span>
										)}
									</pre>
								</CardContent>
							</Card>
						)}
						{currentRun?.reportError && (
							<Alert className="mt-5">
								<AlertTitle>El inventario requiere atención</AlertTitle>
								<AlertDescription>{currentRun.reportError}</AlertDescription>
							</Alert>
						)}
						{currentResults.length > 0 && (
							<Card id="results-card" className="mt-5 overflow-hidden">
								<CardHeader className="border-b bg-muted/15 py-3.5">
									<div className="flex flex-wrap items-center justify-between gap-2">
										<div>
											<CardTitle className="flex items-center gap-2 text-sm">
												<Network className="size-4 text-primary" />
												Hosts observados
											</CardTitle>
											<CardDescription>
												{currentRun
													? `Última ejecución · ${new Date(currentRun.date).toLocaleString()}`
													: "Resultados detectados en esta ejecución"}
											</CardDescription>
										</div>
										<Badge variant="secondary">
											{currentResults.length}{" "}
											{currentResults.length === 1 ? "host" : "hosts"} ·{" "}
											{currentResults.reduce(
												(total, host) =>
													total +
													host.ports.filter((port) => port.state === "open")
														.length,
												0,
											)}{" "}
											puertos abiertos
										</Badge>
									</div>
								</CardHeader>
								<CardContent className="min-w-0">
									<Table className="table-fixed">
										<TableHeader>
											<TableRow>
												<TableHead className="w-[30%] whitespace-normal md:w-1/4">
													Host
												</TableHead>
												<TableHead className="w-20 whitespace-normal">
													Estado
												</TableHead>
												<TableHead className="whitespace-normal">
													Puertos abiertos
												</TableHead>
											</TableRow>
										</TableHeader>
										<TableBody>
											{currentResults.map((host) => {
												const openPorts = host.ports.filter(
													(port) => port.state === "open",
												);
												return (
													<TableRow key={host.address}>
														<TableCell className="align-top whitespace-normal wrap-anywhere">
															<div className="font-mono text-xs font-medium">
																{host.address}
															</div>
															{host.hostname && (
																<div className="text-[11px] text-muted-foreground">
																	{host.hostname}
																</div>
															)}
														</TableCell>
														<TableCell className="align-top whitespace-normal wrap-anywhere">
															<Badge
																variant={
																	host.status === "up"
																		? "success"
																		: host.status === "down"
																			? "warning"
																			: "outline"
																}
															>
																{host.status ?? "respondió"}
															</Badge>
														</TableCell>
														<TableCell className="align-top whitespace-normal wrap-anywhere">
															<div className="flex min-w-0 flex-wrap gap-1.5">
																{openPorts.length ? (
																	openPorts.map((port) => (
																		<Badge
																			key={`${host.address}-${port.protocol}-${port.port}`}
																			variant="secondary"
																			className="max-w-full whitespace-normal wrap-anywhere font-mono text-[10px]"
																		>
																			{port.port}/{port.protocol} ·{" "}
																			{port.service}
																			{port.product ? ` · ${port.product}` : ""}
																			{port.version ? ` ${port.version}` : ""}
																		</Badge>
																	))
																) : (
																	<span className="text-xs text-muted-foreground">
																		Sin puertos abiertos reportados
																	</span>
																)}
															</div>
														</TableCell>
													</TableRow>
												);
											})}
										</TableBody>
									</Table>
								</CardContent>
							</Card>
						)}
						{project?.lastRuns?.length ? (
							<Card id="history-card" className="mt-5 overflow-hidden">
								<CardHeader className="border-b bg-muted/15 py-3.5">
									<CardTitle className="flex items-center gap-2 text-sm">
										<Activity className="size-4 text-primary" />
										Ejecuciones recientes
									</CardTitle>
									<CardDescription>
										Historial compacto guardado en el navegador.
									</CardDescription>
								</CardHeader>
								<CardContent className="divide-y">
									{project.lastRuns.map((run) => (
										<div
											key={run.id}
											className="grid gap-2 py-3 md:grid-cols-[1fr_auto] md:items-center"
										>
											<div className="min-w-0">
												<code className="block truncate text-xs">
													{run.command}
												</code>
												<span className="mt-1 block text-[11px] text-muted-foreground">
													{new Date(run.date).toLocaleString()} ·{" "}
													{run.hosts?.length ?? 0} hosts
												</span>
											</div>
											<Badge
												variant={
													run.state === "completed" ? "success" : "warning"
												}
											>
												{run.state}
											</Badge>
										</div>
									))}
								</CardContent>
							</Card>
						) : null}
						<div className="mt-5 space-y-5">
							{project && (
								<TestChecklist
									key={`checks-${project.id}`}
									project={project}
									phase="enumeration"
								/>
							)}
							<OperationHistory
								key={project?.id ?? "general"}
								projectId={project?.id}
								phase="enumeration"
							/>
						</div>
						<div className="mt-5 flex items-center justify-between text-[11px] text-muted-foreground">
							<span className="flex items-center gap-1.5">
								<LockKeyhole className="size-3" />
								Datos guardados localmente en este navegador
							</span>
							<span>Los reportes extensos se descargan a tu equipo.</span>
						</div>
					</div>
				</main>
			</div>
		</div>
	);
}
function FieldLabel({
	label,
	hint,
	children,
}: {
	label: string;
	hint?: string;
	children: React.ReactNode;
}) {
	const id = useId();
	const fields = Children.toArray(children);
	const controlIndex = fields.findIndex(isValidElement);
	if (controlIndex >= 0) {
		fields[controlIndex] = cloneElement(
			fields[controlIndex] as ReactElement<{ id?: string }>,
			{ id },
		);
	}
	return (
		<div className="grid gap-1.5 text-xs font-medium">
			<label htmlFor={id}>{label}</label>
			{fields}
			{hint && (
				<span className="font-normal leading-relaxed text-muted-foreground">
					{hint}
				</span>
			)}
		</div>
	);
}
