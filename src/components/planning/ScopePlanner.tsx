import { Link } from "@tanstack/react-router";
import { FileDown, Pause, Save, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { isActiveJob } from "../../lib/execution.ts";
import { saveProjectPlan } from "../../lib/planning-project.ts";
import {
	approvalIssues,
	approveScopePlan,
	newScopePlan,
	type ScopePlan,
	scopeLines,
	scopeTechniques,
	targetDecision,
	validateScopePlan,
} from "../../lib/scope.ts";
import { exportWorkspace, type WorkspaceProject } from "../../lib/storage.ts";
import { NewProjectButton } from "../ProjectCreation";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "../ui/card";
import { Checkbox } from "../ui/checkbox";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "../ui/dialog";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "../ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { useWorkspace } from "../WorkspaceProvider";
import { isoDateInput, localDateInput, PlanField } from "./PlanFields";

const statusLabels = {
	draft: "Borrador",
	approved: "Aprobado",
	paused: "Pausado",
	closed: "Cerrado",
};
type PlanTextKey =
	| "organization"
	| "assessor"
	| "authorizer"
	| "authorizationReference"
	| "prohibitedActivities"
	| "stopConditions"
	| "contactName"
	| "contactChannel"
	| "incidentName"
	| "incidentChannel"
	| "dataHandling"
	| "deliverables"
	| "notes";
function download(filename: string, content: string, type = "text/markdown") {
	const url = URL.createObjectURL(new Blob([content], { type }));
	const anchor = document.createElement("a");
	anchor.href = url;
	anchor.download = filename;
	anchor.click();
	URL.revokeObjectURL(url);
}
function seedPlan(project: WorkspaceProject): ScopePlan {
	if (project.plan) return structuredClone(project.plan);
	const plan = newScopePlan();
	plan.notes = project.scope
		? `Alcance anterior (pendiente de revisión): ${project.scope}`
		: "";
	try {
		plan.includes = scopeLines(project.scope);
	} catch {
		/* Legacy scope may be descriptive prose. */
	}
	return plan;
}
export function ScopePlanner() {
	const {
		workspace,
		setWorkspace,
		hydrated,
		storageError,
		execution,
		setProjectDialogOpen,
		setProjectCreationBlocked,
	} = useWorkspace();
	const [selectionLocked, setSelectionLocked] = useState(false);
	const project =
		workspace.projects.find(
			(item) => item.id === workspace.selectedProjectId,
		) ?? workspace.projects[0];
	const active = execution && isActiveJob(execution.state);
	useEffect(() => {
		setProjectCreationBlocked(selectionLocked);
		return () => setProjectCreationBlocked(false);
	}, [selectionLocked, setProjectCreationBlocked]);
	return (
		<div className="grid gap-5">
			{storageError && (
				<Alert variant="destructive">
					<AlertTitle>No se pudo guardar en este navegador</AlertTitle>
					<AlertDescription>{storageError}</AlertDescription>
				</Alert>
			)}
			<div className="flex flex-wrap items-center justify-between gap-3">
				<Select
					value={project?.id ?? ""}
					disabled={selectionLocked || !hydrated || !workspace.projects.length}
					onValueChange={(id) =>
						setWorkspace((current) => ({ ...current, selectedProjectId: id }))
					}
				>
					<SelectTrigger
						className="w-full sm:w-72"
						aria-label="Proyecto del plan"
					>
						<SelectValue placeholder="Selecciona proyecto" />
					</SelectTrigger>
					<SelectContent>
						{workspace.projects.map((item) => (
							<SelectItem key={item.id} value={item.id}>
								{item.name}
							</SelectItem>
						))}
					</SelectContent>
				</Select>
				<div className="flex gap-2">
					<NewProjectButton variant="outline" disabled={selectionLocked} />
					<Button
						variant="outline"
						disabled={!workspace.projects.length}
						onClick={() =>
							download(
								"workspace.json",
								exportWorkspace(workspace),
								"application/json",
							)
						}
					>
						<FileDown className="mr-2 size-4" />
						Exportar proyectos
					</Button>
				</div>
			</div>
			{selectionLocked && (
				<p className="m-0 text-xs text-muted-foreground">
					Guarda o descarta el borrador antes de cambiar de proyecto. El
					borrador sin guardar permanece solo en esta página.
				</p>
			)}
			{!hydrated ? (
				<p>Cargando proyectos…</p>
			) : project ? (
				<ProjectPlan
					key={project.id}
					project={project}
					onDirty={setSelectionLocked}
					active={Boolean(active && execution.projectId === project.id)}
				/>
			) : (
				<Card>
					<CardHeader>
						<CardTitle>Primero define el compromiso de prueba</CardTitle>
						<CardDescription>
							Crea un proyecto para registrar autorización, alcance y reglas
							antes de enumerar.
						</CardDescription>
					</CardHeader>
					<CardContent>
						<Button onClick={() => setProjectDialogOpen(true)}>
							Crear proyecto
						</Button>
					</CardContent>
				</Card>
			)}
		</div>
	);
}

function ProjectPlan({
	project,
	onDirty,
	active,
}: {
	project: WorkspaceProject;
	onDirty: (dirty: boolean) => void;
	active: boolean;
}) {
	const { setWorkspace, cancelExecution, storageError } = useWorkspace();
	const [draft, setDraft] = useState(() => seedPlan(project));
	const [name, setName] = useState(project.name);
	const [includes, setIncludes] = useState(() =>
		seedPlan(project).includes.join("\n"),
	);
	const [excludes, setExcludes] = useState(() =>
		seedPlan(project).excludes.join("\n"),
	);
	const [dirty, setDirty] = useState(false);
	const [message, setMessage] = useState("");
	const [error, setError] = useState("");
	const [approvalOpen, setApprovalOpen] = useState(false);
	const [attested, setAttested] = useState(false);
	const [deleteOpen, setDeleteOpen] = useState(false);
	const [testTarget, setTestTarget] = useState("");
	const [decision, setDecision] = useState("");
	const [tab, setTab] = useState("agreement");
	const [pausing, setPausing] = useState(false);
	const saved = project.plan;
	function touch() {
		setDirty(true);
		onDirty(true);
		setMessage("");
		setError("");
	}
	function update<K extends keyof ScopePlan>(key: K, value: ScopePlan[K]) {
		setDraft((current) => ({ ...current, [key]: value }));
		touch();
	}
	function materialize() {
		if (!name.trim() || name.length > 200)
			throw new Error("Indica un nombre de proyecto de hasta 200 caracteres.");
		return validateScopePlan({
			...draft,
			includes: scopeLines(includes),
			excludes: scopeLines(excludes),
			revision: dirty ? (saved?.revision ?? 0) + 1 : draft.revision,
			status: dirty ? "draft" : draft.status,
			approvalAttested: dirty ? false : draft.approvalAttested,
			approvedAt: dirty ? undefined : draft.approvedAt,
		});
	}
	function persist(plan: ScopePlan, text: string) {
		setWorkspace((current) => saveProjectPlan(current, project.id, name, plan));
		setDraft(plan);
		setDirty(false);
		onDirty(false);
		setError("");
		setMessage(text);
	}
	function save() {
		try {
			const plan = materialize();
			persist(
				{
					...plan,
					status: "draft",
					approvalAttested: false,
					approvedAt: undefined,
				},
				"Borrador actualizado. Debes registrar la aprobación antes de ejecutar.",
			);
		} catch (error) {
			setError(error instanceof Error ? error.message : "No se pudo guardar.");
		}
	}
	function approve() {
		try {
			const plan = approveScopePlan(materialize(), attested);
			persist(
				plan,
				"Aprobación registrada. Solo se permite ejecutar dentro de la ventana y las reglas acordadas.",
			);
			setApprovalOpen(false);
			setAttested(false);
		} catch (error) {
			setError(error instanceof Error ? error.message : "Revisa el plan.");
			setApprovalOpen(false);
		}
	}
	function discard() {
		const plan = seedPlan(project);
		setDraft(plan);
		setName(project.name);
		setIncludes(plan.includes.join("\n"));
		setExcludes(plan.excludes.join("\n"));
		setDirty(false);
		onDirty(false);
		setError("");
		setMessage("");
	}
	async function pause() {
		setPausing(true);
		try {
			persist(
				{ ...materialize(), status: "paused" },
				active
					? "Plan pausado. Se solicitó cancelar la ejecución; revisa la confirmación en Enumeración."
					: "Plan pausado; no permite nuevas ejecuciones.",
			);
			if (active) await cancelExecution();
		} catch (error) {
			setError(error instanceof Error ? error.message : "No se pudo pausar.");
		} finally {
			setPausing(false);
		}
	}
	function exportPlan(revision?: ScopePlan) {
		const saved = revision ?? project.plan;
		if (!saved || (!revision && dirty)) {
			setError(
				"Guarda el plan antes de exportarlo para conservar su revisión exacta.",
			);
			return;
		}
		const sections = [
			[
				"Estado",
				`${statusLabels[saved.status]} · revisión ${saved.revision} · registro ${saved.approvedAt ?? "sin aprobación"}`,
			],
			["Organización / propietario", saved.organization],
			["Objetivo", saved.objective],
			["Tipo", saved.assessmentType],
			["Responsable de las pruebas", saved.assessor],
			["Persona que autoriza", saved.authorizer],
			["Referencia de autorización escrita", saved.authorizationReference],
			["Activos incluidos", saved.includes.join("\n")],
			["Exclusiones", saved.excludes.join("\n") || "Ninguna registrada"],
			["Ventana (UTC)", `${saved.windowStart} → ${saved.windowEnd}`],
			["Origen y conectividad", saved.sourceDescription],
			["Coordinación", `${saved.contactName} · ${saved.contactChannel}`],
			["Incidentes", `${saved.incidentName} · ${saved.incidentChannel}`],
			[
				"Reconocimiento pasivo en fuentes públicas",
				saved.passiveRecon ? "Permitido" : "No permitido",
			],
			[
				"Técnicas",
				Object.entries(saved.techniques)
					.filter(([, allowed]) => allowed)
					.map(([key]) => scopeTechniques[key as keyof typeof scopeTechniques])
					.join(", "),
			],
			[
				"Límites",
				`Puertos: ${saved.allowedPorts}; direcciones por ejecución: ${saved.maxHosts}; paquetes/s: ${saved.maxRate}; timeout: ${saved.maxDurationSeconds}s`,
			],
			[
				"Verificaciones de análisis",
				`Nikto: ${saved.analysisTools?.nikto ? "permitido" : "no permitido"}; testssl.sh: ${saved.analysisTools?.testssl ? "permitido" : "no permitido"}. Una IP y puerto por prueba. Estos adaptadores no limitan paquetes/s; requieren aceptar su ritmo propio. Nikto espera 1 segundo entre pruebas.`,
			],
			["Actividades prohibidas", saved.prohibitedActivities],
			["Criterios de parada", saved.stopConditions],
			[
				"Evidencia",
				`${saved.dataHandling}\nRetención acordada: ${saved.retentionDays} días (borrado manual).`,
			],
			["Entregables", saved.deliverables],
			["Notas", saved.notes],
		];
		download(
			`plan-${project.id}-r${saved.revision}.md`,
			`# Plan de pruebas: ${project.name}\n\n${sections.map(([title, body]) => `## ${title}\n\n${body}`).join("\n\n")}\n\nRegistro operativo local; la autorización firmada se conserva en la referencia indicada.\n`,
		);
	}
	let readiness: string[];
	try {
		readiness = approvalIssues(materialize());
	} catch (error) {
		readiness = [error instanceof Error ? error.message : "Revisa los campos."];
	}
	const windowActive =
		saved &&
		Date.now() >= Date.parse(saved.windowStart) &&
		Date.now() < Date.parse(saved.windowEnd);
	const fields = (
		definitions: readonly (readonly [PlanTextKey, string, string?])[],
		multiline = false,
	) =>
		definitions.map(([key, label, hint]) => (
			<PlanField
				key={key}
				label={label}
				value={String(draft[key] ?? "")}
				multiline={multiline}
				hint={hint}
				onChange={(value) => update(key, value)}
			/>
		));
	return (
		<>
			<Card>
				<CardHeader>
					<div className="flex flex-wrap items-center justify-between gap-3">
						<div>
							<CardTitle>Plan de pruebas y reglas de compromiso</CardTitle>
							<CardDescription className="mt-2">
								Define lo acordado con el propietario. La referencia documental
								respalda el registro de autorización.
							</CardDescription>
						</div>
						<Badge
							variant={
								dirty
									? "warning"
									: saved?.status === "approved"
										? "success"
										: saved?.status === "closed"
											? "outline"
											: "warning"
							}
						>
							{dirty
								? "Cambios sin guardar"
								: statusLabels[saved?.status ?? "draft"]}{" "}
							· r{saved?.revision ?? 1}
						</Badge>
					</div>
				</CardHeader>
				<CardContent className="grid gap-5">
					{active && (
						<Alert>
							<AlertTitle>Ejecución activa</AlertTitle>
							<AlertDescription>
								Los cambios se aplican a nuevas ejecuciones. Pausar solicita
								cancelar la actual y exige comprobar su terminación.
							</AlertDescription>
						</Alert>
					)}
					{saved?.status === "approved" && !windowActive && (
						<Alert variant="warning">
							<AlertTitle>Fuera de la ventana autorizada</AlertTitle>
							<AlertDescription>
								La aprobación está registrada, pero la ventana aún no ha
								empezado o ya terminó.
							</AlertDescription>
						</Alert>
					)}
					{error && (
						<Alert variant="destructive">
							<AlertTitle>Revisa el plan</AlertTitle>
							<AlertDescription className="whitespace-pre-line">
								{error}
							</AlertDescription>
						</Alert>
					)}
					{message && !storageError && (
						<Alert>
							<AlertDescription>{message}</AlertDescription>
						</Alert>
					)}
					<Tabs value={tab} onValueChange={setTab}>
						<TabsList className="h-auto w-full flex-wrap justify-start">
							<TabsTrigger value="agreement">Acuerdo</TabsTrigger>
							<TabsTrigger value="assets">Activos</TabsTrigger>
							<TabsTrigger value="rules">Reglas</TabsTrigger>
							<TabsTrigger value="logistics">
								Preparación y evidencia
							</TabsTrigger>
						</TabsList>
						<TabsContent value="agreement" className="mt-5 grid gap-5">
							<PlanField
								label="Nombre del proyecto"
								value={name}
								onChange={(value) => {
									setName(value);
									touch();
								}}
							/>
							<div className="grid gap-5 lg:grid-cols-2">
								{fields([
									["organization", "Organización o propietario de los activos"],
									["assessor", "Responsable / equipo que realiza las pruebas"],
									["authorizer", "Responsable con autoridad para autorizar"],
									[
										"authorizationReference",
										"Referencia de autorización escrita",
										"Contrato, carta firmada o ticket aprobado. Guarda el documento fuera de la app; aquí registra su referencia.",
									],
								])}
							</div>
							<PlanField
								label="Objetivo y criterios de éxito"
								value={draft.objective}
								multiline
								onChange={(value) => update("objective", value)}
								hint="Qué preguntas debe responder la evaluación y qué resultado se entregará."
							/>
							<div className="grid gap-2">
								<span id={`type-${project.id}`} className="text-xs font-medium">
									Perspectiva de la evaluación
								</span>
								<Select
									value={draft.assessmentType}
									onValueChange={(value) =>
										update(
											"assessmentType",
											value as ScopePlan["assessmentType"],
										)
									}
								>
									<SelectTrigger
										aria-labelledby={`type-${project.id}`}
										className="w-full sm:w-64"
									>
										<SelectValue />
									</SelectTrigger>
									<SelectContent>
										<SelectItem value="internal">Interna</SelectItem>
										<SelectItem value="external">Externa</SelectItem>
									</SelectContent>
								</Select>
							</div>
							<p className="m-0 text-xs text-muted-foreground">
								La modalidad y el objetivo documentan el compromiso completo.
								Este MVP ejecuta enumeración Nmap; otras fases conservan su
								autorización y flujo propios.
							</p>
						</TabsContent>
						<TabsContent value="assets" className="mt-5 grid gap-5">
							<div className="grid gap-5 lg:grid-cols-2">
								<PlanField
									label="Activos incluidos"
									value={includes}
									multiline
									placeholder="192.168.56.10\n192.168.56.0/24\n2001:db8::/64\napp.empresa.test"
									onChange={(value) => {
										setIncludes(value);
										touch();
									}}
									hint="Una IP, CIDR o nombre DNS exacto por línea. Incluir un dominio no incluye automáticamente subdominios, enlaces ni sistemas de terceros."
								/>
								<PlanField
									label="Activos excluidos / no tocar"
									value={excludes}
									multiline
									onChange={(value) => {
										setExcludes(value);
										touch();
									}}
									hint="Las exclusiones prevalecen. Un rango que se solape con una exclusión se bloquea; usa destinos explícitos permitidos."
								/>
							</div>
							<Alert>
								<AlertDescription>
									Los nombres se resuelven en el ejecutor y se comprueban contra
									exclusiones antes de iniciar. El comando efectivo usa una IP
									fijada. Registra explícitamente permisos de proveedores o
									terceros en las notas cuando corresponda.
								</AlertDescription>
							</Alert>
							<div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
								<PlanField
									label="Comprobar pertenencia de un objetivo"
									value={testTarget}
									onChange={setTestTarget}
								/>
								<Button
									variant="outline"
									className="self-end"
									onClick={() => {
										try {
											const result = targetDecision(testTarget, materialize());
											setDecision(
												`${result.allowed ? "Incluido" : "Bloqueado"}: ${result.reason}${result.dns ? ". La comprobación DNS y sus exclusiones por IP se realizan al ejecutar." : ` · ${result.count.toString()} ${result.count === 1n ? "dirección" : "direcciones"}`}`,
											);
										} catch (error) {
											setDecision(
												error instanceof Error
													? error.message
													: "Objetivo inválido",
											);
										}
									}}
								>
									Comprobar alcance
								</Button>
							</div>
							{decision && <output className="m-0 text-xs">{decision}</output>}
						</TabsContent>
						<TabsContent value="rules" className="mt-5 grid gap-5">
							<div className="grid gap-3 sm:grid-cols-2">
								<label
									htmlFor={`passive-${project.id}`}
									className="flex cursor-pointer items-center gap-3 rounded-lg border p-3 text-sm"
								>
									<Checkbox
										id={`passive-${project.id}`}
										checked={draft.passiveRecon}
										onCheckedChange={(checked) =>
											update("passiveRecon", checked === true)
										}
									/>
									Reconocimiento pasivo en fuentes públicas
								</label>
								{(["nikto", "testssl"] as const).map((tool) => (
									<label
										key={tool}
										htmlFor={`analysis-${tool}-${project.id}`}
										className="flex items-start gap-2 text-sm"
									>
										<Checkbox
											id={`analysis-${tool}-${project.id}`}
											checked={draft.analysisTools?.[tool] ?? false}
											onCheckedChange={(checked) =>
												update("analysisTools", {
													nikto: draft.analysisTools?.nikto ?? false,
													testssl: draft.analysisTools?.testssl ?? false,
													[tool]: checked === true,
												})
											}
										/>
										<span>
											Permitir verificaciones con{" "}
											{tool === "nikto" ? "Nikto" : "testssl.sh"}. Una IP y
											puerto, con ritmo propio de la herramienta (sin límite de
											paquetes/s; Nikto pausa 1 segundo entre pruebas). Revisar
											las actividades prohibidas del compromiso.
										</span>
									</label>
								))}
								{Object.entries(scopeTechniques).map(([key, label]) => (
									<label
										key={key}
										htmlFor={`tech-${key}-${project.id}`}
										className="flex cursor-pointer items-center gap-3 rounded-lg border p-3 text-sm"
									>
										<Checkbox
											id={`tech-${key}-${project.id}`}
											checked={
												draft.techniques[key as keyof typeof scopeTechniques]
											}
											onCheckedChange={(checked) =>
												update("techniques", {
													...draft.techniques,
													[key]: checked === true,
												})
											}
										/>
										{label}
									</label>
								))}
							</div>
							<div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
								<PlanField
									label="Puertos permitidos (TCP/UDP)"
									value={draft.allowedPorts}
									onChange={(value) => update("allowedPorts", value)}
									hint="Números y rangos. 1-65535 permite todos los puertos habituales."
								/>
								{(
									[
										[
											"maxHosts",
											"Máximo de direcciones por ejecución",
											1,
											4096,
										],
										["maxRate", "Máximo de paquetes por segundo", 1, 100000],
										[
											"maxDurationSeconds",
											"Timeout máximo en segundos",
											5,
											86400,
										],
									] as const
								).map(([key, label, min, max]) => (
									<PlanField
										key={key}
										label={label}
										type="number"
										min={min}
										max={max}
										value={draft[key]}
										onChange={(value) => update(key, Number(value))}
									/>
								))}
							</div>
							{fields(
								[
									[
										"prohibitedActivities",
										"Actividades prohibidas / restricciones adicionales",
									],
									[
										"stopConditions",
										"Criterios de parada y condiciones de reanudación",
									],
								],
								true,
							)}
							<Alert>
								<AlertTitle>Controles que aplica el MVP</AlertTitle>
								<AlertDescription>
									Comprueba activos, exclusiones, técnicas, puertos, tasa y
									duración antes de Nmap. Solo una ejecución por navegador. NSE,
									-A, destinos aleatorios, archivos de entrada, reanudación y
									opciones que deriven otros destinos requieren adaptadores de
									validación y quedan bloqueados. Los criterios de parada por
									impacto requieren supervisión del operador.
								</AlertDescription>
							</Alert>
						</TabsContent>
						<TabsContent value="logistics" className="mt-5 grid gap-5">
							<div className="grid gap-5 sm:grid-cols-2">
								<PlanField
									label="Inicio de la ventana"
									type="datetime-local"
									value={localDateInput(draft.windowStart)}
									onChange={(value) =>
										update("windowStart", isoDateInput(value))
									}
								/>
								<PlanField
									label="Fin de la ventana"
									type="datetime-local"
									value={localDateInput(draft.windowEnd)}
									onChange={(value) => update("windowEnd", isoDateInput(value))}
								/>
							</div>
							<p className="m-0 text-xs text-muted-foreground">
								Horas en la zona local del navegador (
								{Intl.DateTimeFormat().resolvedOptions().timeZone}); se guardan
								y exportan en UTC. La ejecución debe finalizar dentro de esta
								ventana.
							</p>
							<PlanField
								label="Origen de las pruebas y conectividad acordada"
								value={draft.sourceDescription}
								multiline
								onChange={(value) => update("sourceDescription", value)}
								hint="Kali / SSH, IP de origen acordada, VPN, entorno y restricciones de red. La app no comprueba automáticamente la IP pública o la autorización de terceros."
							/>
							<div className="grid gap-5 lg:grid-cols-2">
								{fields([
									["contactName", "Contacto de coordinación"],
									[
										"contactChannel",
										"Canal de coordinación (correo / teléfono)",
									],
									["incidentName", "Contacto de incidentes / emergencia"],
									["incidentChannel", "Canal inmediato para incidentes"],
								])}
							</div>
							{fields(
								[
									[
										"dataHandling",
										"Clasificación, destinatarios y manejo de evidencia",
									],
									["deliverables", "Entregables y criterios de cierre"],
									[
										"notes",
										"Supuestos, dependencias, permisos de terceros y notas",
									],
								],
								true,
							)}
							<PlanField
								label="Retención acordada de evidencia (días)"
								type="number"
								min={1}
								max={3650}
								value={draft.retentionDays}
								onChange={(value) => update("retentionDays", Number(value))}
								hint="Registra el acuerdo. La app no borra automáticamente los datos ni protege los archivos que exportes; aplica la política de almacenamiento y eliminación acordada."
							/>
						</TabsContent>
					</Tabs>
					<div className="flex flex-wrap gap-2 border-t pt-5">
						<Button onClick={save} disabled={!dirty && Boolean(saved)}>
							<Save className="mr-2 size-4" />
							Guardar borrador
						</Button>
						<Button variant="outline" disabled={!dirty} onClick={discard}>
							Descartar cambios
						</Button>
						<Button
							disabled={
								readiness.length > 0 || (!dirty && saved?.status === "approved")
							}
							onClick={() => {
								setAttested(false);
								setApprovalOpen(true);
							}}
						>
							<ShieldCheck className="mr-2 size-4" />
							Registrar aprobación
						</Button>
						<Button
							variant="outline"
							disabled={!saved || dirty}
							onClick={() => exportPlan()}
						>
							<FileDown className="mr-2 size-4" />
							Exportar plan
						</Button>
						<Button
							variant="outline"
							disabled={
								!saved ||
								dirty ||
								pausing ||
								saved.status === "paused" ||
								saved.status === "closed"
							}
							onClick={() => void pause()}
						>
							<Pause className="mr-2 size-4" />
							{active ? "Pausar y solicitar cancelación" : "Pausar plan"}
						</Button>
						<Button
							variant="outline"
							disabled={!saved || dirty || active || saved.status === "closed"}
							onClick={() =>
								persist(
									{ ...materialize(), status: "closed" },
									"Plan cerrado; se conserva la evidencia y se bloquean nuevas ejecuciones.",
								)
							}
						>
							Cerrar plan
						</Button>
						<Button
							variant="ghost"
							disabled={active || dirty}
							onClick={() => setDeleteOpen(true)}
						>
							<Trash2 className="mr-2 size-4" />
							Eliminar proyecto
						</Button>
						<Button variant="outline" disabled={dirty} asChild>
							<Link to="/">Ir a Enumeración</Link>
						</Button>
					</div>
					{readiness.length > 0 && (
						<details className="rounded-lg border p-3 text-xs">
							<summary className="cursor-pointer font-medium">
								{readiness.length === 1
									? "Falta 1 dato"
									: `Faltan ${readiness.length} datos`}{" "}
								para registrar la aprobación
							</summary>
							<ul className="mb-0 mt-3 list-disc space-y-1 pl-4">
								{readiness.map((issue) => (
									<li key={issue}>{issue}</li>
								))}
							</ul>
						</details>
					)}
					{Boolean(project.planHistory?.length) && (
						<details className="rounded-lg border p-3 text-xs">
							<summary className="cursor-pointer font-medium">
								Revisiones anteriores con aprobación registrada
							</summary>
							<div className="mt-3 grid gap-2">
								{project.planHistory?.map((plan) => (
									<div
										key={plan.revision}
										className="flex flex-wrap items-center justify-between gap-2"
									>
										<span>
											Revisión {plan.revision} · {statusLabels[plan.status]} ·{" "}
											{plan.approvedAt
												? new Date(plan.approvedAt).toLocaleString()
												: "Sin fecha"}
										</span>
										<Button
											variant="outline"
											size="sm"
											onClick={() => exportPlan(plan)}
										>
											Descargar revisión {plan.revision}
										</Button>
									</div>
								))}
							</div>
							<p className="mb-0 mt-3 text-muted-foreground">
								Se conservan hasta diez revisiones anteriores. Exporta el
								proyecto para archivar el historial antes de superar este
								límite.
							</p>
						</details>
					)}
					<p className="m-0 text-xs leading-relaxed text-muted-foreground">
						Editar y guardar el plan invalida su aprobación anterior. Los datos
						se guardan en localStorage y se incluyen en la exportación del
						proyecto. Basado en{" "}
						<a
							className="text-primary underline"
							href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf"
							target="_blank"
							rel="noreferrer"
						>
							NIST SP 800-115, planificación y reglas de compromiso
						</a>
						.
					</p>
				</CardContent>
			</Card>
			<Dialog open={approvalOpen} onOpenChange={setApprovalOpen}>
				<DialogContent>
					<DialogHeader>
						<DialogTitle>Registrar autorización del plan</DialogTitle>
						<DialogDescription>
							La app registra tu confirmación de una autorización obtenida fuera
							de ella. Conserva el documento en la referencia indicada. Se
							aplicarán los límites de esta revisión.
						</DialogDescription>
					</DialogHeader>
					<label
						htmlFor={`approval-${project.id}`}
						className="flex items-start gap-3 text-sm leading-relaxed"
					>
						<Checkbox
							id={`approval-${project.id}`}
							checked={attested}
							onCheckedChange={(value) => setAttested(value === true)}
						/>
						<span>
							Confirmo que dispongo de autorización escrita de los responsables
							de los activos, incluidos terceros cuando corresponda, para este
							alcance, técnicas y ventana.
						</span>
					</label>
					<DialogFooter>
						<Button variant="outline" onClick={() => setApprovalOpen(false)}>
							Volver a revisar
						</Button>
						<Button disabled={!attested} onClick={approve}>
							Registrar aprobación
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>
			<Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
				<DialogContent>
					<DialogHeader>
						<DialogTitle>Eliminar {project.name}</DialogTitle>
						<DialogDescription>
							Se eliminarán su plan, objetivos e historial de este navegador.
							Exporta primero si necesitas conservarlos.
						</DialogDescription>
					</DialogHeader>
					<DialogFooter>
						<Button variant="outline" onClick={() => setDeleteOpen(false)}>
							Cancelar
						</Button>
						<Button
							variant="destructive"
							onClick={() => {
								setWorkspace((current) => {
									const projects = current.projects.filter(
										(item) => item.id !== project.id,
									);
									return {
										projects,
										selectedProjectId: projects[0]?.id ?? null,
									};
								});
								onDirty(false);
							}}
						>
							Eliminar proyecto y datos
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>
		</>
	);
}
