import { Link, useBlocker } from "@tanstack/react-router";
import { Download, Radar } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { ReconAsset, ReconQuery, ReconResult } from "#/lib/recon";
import {
	deleteReconEvidence,
	editReconAsset,
	promoteReconAsset,
	reconMarkdown,
	saveReconResult,
} from "#/lib/recon-project";
import { exportWorkspace, type WorkspaceData } from "#/lib/storage";
import { mergeCheckHistory } from "#/lib/test-checklist";
import { collectPassiveRecon } from "#/server/recon";
import { OperationHistory } from "../OperationHistory";
import { TestChecklist } from "../TestChecklist";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
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
import { useWorkspace } from "../WorkspaceProvider";
import { ReconCollector } from "./ReconCollector";
import { ReconInventory } from "./ReconInventory";

function download(content: string, name: string, mime: string) {
	const url = URL.createObjectURL(new Blob([content], { type: mime }));
	const link = document.createElement("a");
	link.href = url;
	link.download = name;
	link.click();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function ReconWorkspace() {
	const {
		workspace,
		recordFailure,
		beginOperation,
		finishOperation,
		setWorkspace,
		hydrated,
		storageError,
		getKaliAccess,
		setProjectCreationBlocked,
	} = useWorkspace();
	const latest = useRef(workspace);
	useEffect(() => {
		latest.current = workspace;
	}, [workspace]);
	const [busy, setBusy] = useState(false);
	useEffect(() => {
		setProjectCreationBlocked(busy);
		return () => setProjectCreationBlocked(false);
	}, [busy, setProjectCreationBlocked]);
	const busyRef = useRef(false);
	const blocker = useBlocker({
		shouldBlockFn: () => busyRef.current,
		enableBeforeUnload: () => busyRef.current,
		withResolver: true,
	});
	useEffect(() => {
		if (!busy && blocker.status === "blocked") blocker.proceed();
	}, [busy, blocker]);
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	const [failedQuery, setFailedQuery] = useState<ReconQuery>();
	const project = workspace.projects.find(
		(p) => p.id === workspace.selectedProjectId,
	);
	// Only changed recognition/target fields are committed. Execution history may
	// keep updating independently while an external request is in flight.
	function commit(
		id: string,
		update: (current: WorkspaceData) => WorkspaceData,
		includeTargets = false,
	) {
		const next = update(latest.current);
		const changed = next.projects.find((p) => p.id === id);
		if (!changed) throw new Error("El proyecto ya no existe.");
		latest.current = next;
		setWorkspace((current) => ({
			...current,
			projects: current.projects.map((p) =>
				p.id === id
					? {
							...p,
							recon: changed.recon,
							checkHistory: mergeCheckHistory(
								p.checkHistory,
								changed.checkHistory,
							),
							...(includeTargets ? { targets: changed.targets } : {}),
						}
					: p,
			),
		}));
	}
	function save(id: string, result: ReconResult, notes = "") {
		commit(id, (current) => saveReconResult(current, id, result, notes));
		setError("");
		setMessage(
			`Evidencia registrada: ${result.assets.length} nombres o direcciones aportados. Se conserva el proyecto original de la consulta.`,
		);
	}
	async function query(input: ReconQuery) {
		if (!project?.plan || busyRef.current) return;
		const projectId = project.id;
		const plan = structuredClone(project.plan);
		busyRef.current = true;
		setBusy(true);
		setError("");
		setMessage("");
		setFailedQuery(undefined);
		let stage = "Comprobar conexión y autorización";
		const target =
			input.source === "tls" && input.port && input.port !== 443
				? `${input.domain.includes(":") ? `[${input.domain}]` : input.domain}:${input.port}`
				: input.domain;
		const attemptId = beginOperation(projectId, {
			phase: "recon",
			stage: "Consultar fuente",
			source: input.source,
			target,
			scopeRevision: plan.revision,
			error: "Respuesta pendiente de confirmar.",
		});
		try {
			const access = getKaliAccess();
			stage = "Consultar fuente";
			const result = await collectPassiveRecon({
				data: { ...access, query: input, plan },
			});
			stage = "Guardar evidencia";
			save(projectId, result);
			for (const issue of result.issues ?? [])
				recordFailure(projectId, {
					phase: "recon",
					...issue,
					source: input.source,
					target,
					scopeRevision: plan.revision,
				});
		} catch (e) {
			recordFailure(projectId, {
				id: attemptId,
				phase: "recon",
				stage,
				source: input.source,
				target,
				scopeRevision: plan.revision,
				error:
					e instanceof Error ? e.message : "No se pudo recopilar la fuente.",
			});
			setFailedQuery(input);
			setError(
				e instanceof Error ? e.message : "No se pudo recopilar la fuente.",
			);
		} finally {
			finishOperation(attemptId);
			busyRef.current = false;
			setBusy(false);
		}
	}
	function review(id: string, status: ReconAsset["status"], note: string) {
		if (!project) return;
		try {
			commit(project.id, (current) =>
				editReconAsset(current, project.id, id, status, note),
			);
			setError("");
			setMessage("Revisión del activo guardada.");
		} catch (e) {
			recordFailure(project.id, {
				phase: "recon",
				stage: "Guardar revisión",
				target: id,
				scopeRevision: project.plan?.revision,
				error: e instanceof Error ? e.message : "No se pudo guardar.",
			});
			setError(e instanceof Error ? e.message : "No se pudo guardar.");
		}
	}
	function promote(id: string) {
		if (!project) return;
		try {
			commit(
				project.id,
				(current) => promoteReconAsset(current, project.id, id),
				true,
			);
			setError("");
			setMessage(
				"Activo agregado como objetivo de Enumeración; todavía no se ha ejecutado ninguna prueba.",
			);
		} catch (e) {
			recordFailure(project.id, {
				phase: "recon",
				stage: "Promover activo",
				target: id,
				scopeRevision: project.plan?.revision,
				error: e instanceof Error ? e.message : "No se pudo agregar.",
			});
			setError(e instanceof Error ? e.message : "No se pudo agregar.");
		}
	}
	function remove(id: string) {
		if (!project) return;
		try {
			commit(project.id, (current) =>
				deleteReconEvidence(current, project.id, id),
			);
			setError("");
			setMessage("Evidencia eliminada.");
		} catch (e) {
			recordFailure(project.id, {
				phase: "recon",
				stage: "Eliminar evidencia",
				target: id,
				scopeRevision: project.plan?.revision,
				error: e instanceof Error ? e.message : "No se pudo eliminar.",
			});
			setError(e instanceof Error ? e.message : "No se pudo eliminar.");
		}
	}
	if (!hydrated)
		return <p className="text-sm text-muted-foreground">Cargando proyectos…</p>;
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
						<DialogTitle>Consulta de reconocimiento en curso</DialogTitle>
						<DialogDescription>
							Se guardará la respuesta antes de cambiar de página. La consulta
							tiene un timeout máximo de 60 segundos; al terminar continuará la
							navegación.
						</DialogDescription>
					</DialogHeader>
					<DialogFooter>
						<Button variant="outline" onClick={() => blocker.reset?.()}>
							Permanecer aquí
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>
			{storageError && (
				<Alert variant="destructive">
					<AlertDescription>{storageError}</AlertDescription>
				</Alert>
			)}
			<div className="flex min-w-0 flex-wrap items-center gap-3">
				<Select
					value={project?.id ?? ""}
					disabled={busy || !workspace.projects.length}
					onValueChange={(id) => {
						setWorkspace((current) => ({ ...current, selectedProjectId: id }));
						setMessage("");
						setError("");
						setFailedQuery(undefined);
					}}
				>
					<SelectTrigger
						aria-label="Proyecto de reconocimiento"
						className="w-full sm:w-80"
					>
						<SelectValue placeholder="Selecciona proyecto" />
					</SelectTrigger>
					<SelectContent>
						{workspace.projects.map((p) => (
							<SelectItem value={p.id} key={p.id}>
								{p.name}
							</SelectItem>
						))}
					</SelectContent>
				</Select>
				<Button variant="outline" asChild>
					<Link to="/alcance">Revisar alcance</Link>
				</Button>
				<Button
					variant="outline"
					disabled={
						!(
							project?.recon?.evidence.length ||
							project?.checkHistory?.some((c) => c.phase === "recon") ||
							project?.failures?.some((f) => f.phase === "recon")
						)
					}
					onClick={() => {
						if (project)
							download(
								reconMarkdown(project),
								`reconocimiento-${project.id}.md`,
								"text/markdown;charset=utf-8",
							);
					}}
				>
					<Download className="size-4" />
					Informe Markdown
				</Button>
				<Button
					variant="outline"
					disabled={!workspace.projects.length}
					onClick={() => {
						try {
							download(
								exportWorkspace(workspace),
								"recon-workspace.json",
								"application/json",
							);
						} catch (e) {
							recordFailure(project?.id ?? null, {
								phase: "recon",
								stage: "Exportar proyectos",
								error: e instanceof Error ? e.message : "No se pudo exportar.",
							});
							setError(e instanceof Error ? e.message : "No se pudo exportar.");
						}
					}}
				>
					<Download className="size-4" />
					Exportar proyectos
				</Button>
			</div>
			{project && (
				<TestChecklist
					key={`checks-${project.id}`}
					project={project}
					phase="recon"
				/>
			)}
			<OperationHistory
				key={project?.id ?? "general"}
				projectId={project?.id}
				phase="recon"
			/>
			{!project ? (
				<div className="grid justify-items-center gap-3 rounded-xl border border-dashed p-10 text-center">
					<Radar className="size-6 text-primary" />
					<p className="m-0 text-sm text-muted-foreground">
						Crea un proyecto y define su alcance para comenzar el
						reconocimiento.
					</p>
					<Button asChild>
						<Link to="/alcance">Crear proyecto</Link>
					</Button>
				</div>
			) : (
				<>
					<div className="grid gap-3 sm:grid-cols-3">
						{[
							["Fuentes registradas", project.recon?.evidence.length ?? 0],
							["Activos candidatos", project.recon?.assets.length ?? 0],
							[
								"Revisados",
								project.recon?.assets.filter((a) => a.status === "reviewed")
									.length ?? 0,
							],
						].map(([label, count]) => (
							<div className="rounded-xl border bg-card p-4" key={label}>
								<div className="text-xs text-muted-foreground">{label}</div>
								<div className="mt-2 text-2xl font-semibold">{count}</div>
							</div>
						))}
					</div>
					<div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
						<Badge variant="outline">
							Reconocimiento · DNS, fuentes públicas y TLS
						</Badge>
						<span>
							Plan{" "}
							{project.plan
								? `r${project.plan.revision} · ${{ approved: "aprobado", draft: "borrador", paused: "pausado", closed: "cerrado" }[project.plan.status]}`
								: "sin definir"}
						</span>
						<span>· Hasta 100 evidencias y 2500 activos por proyecto</span>
					</div>
					{error && (
						<Alert variant="destructive">
							<AlertDescription>{error}</AlertDescription>
						</Alert>
					)}
					{message && !storageError && (
						<output
							className="rounded-lg border bg-card p-3 text-sm"
							aria-live="polite"
						>
							{message}
						</output>
					)}
					<ReconCollector
						key={`collector-${project.id}`}
						project={project}
						busy={busy}
						failedQuery={failedQuery}
						onQuery={query}
						onSave={(result, notes) => save(project.id, result, notes)}
					/>
					<ReconInventory
						key={`inventory-${project.id}`}
						project={project}
						busy={busy}
						onReview={review}
						onPromote={promote}
						onDelete={remove}
					/>
				</>
			)}
		</div>
	);
}
