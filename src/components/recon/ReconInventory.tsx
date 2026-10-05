import { Link } from "@tanstack/react-router";
import {
	ArrowRight,
	Copy,
	ExternalLink,
	LayoutGrid,
	List,
	Pencil,
	Trash2,
} from "lucide-react";
import { useState } from "react";
import { type ReconAsset, reconSources } from "#/lib/recon";
import { promotionIssue, reconMarkdown } from "#/lib/recon-project";
import { redactText } from "#/lib/redaction";
import { targetDecision } from "#/lib/scope";
import type { WorkspaceProject } from "#/lib/storage";
import { PlanField } from "../planning/PlanFields";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "../ui/card";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "../ui/dialog";
import { Input } from "../ui/input";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "../ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { useWorkspace } from "../WorkspaceProvider";

const statuses = {
	candidate: "Pendiente de revisión",
	reviewed: "Revisado",
	discarded: "Descartado",
} as const;
export function ReconInventory({
	project,
	busy,
	onReview,
	onPromote,
	onDelete,
}: {
	project: WorkspaceProject;
	busy: boolean;
	onReview: (id: string, status: ReconAsset["status"], note: string) => void;
	onPromote: (id: string) => void;
	onDelete: (id: string) => void;
}) {
	const [search, setSearch] = useState("");
	const [filter, setFilter] = useState("all");
	const [page, setPage] = useState(0);
	const [editing, setEditing] = useState<ReconAsset | null>(null);
	const [deleteId, setDeleteId] = useState("");
	const [tab, setTab] = useState("assets");
	const [layout, setLayout] = useState<"grid" | "list">("grid");
	const { recordFailure } = useWorkspace();
	const [copying, setCopying] = useState(false);
	const [copyMessage, setCopyMessage] = useState("");
	const [copyError, setCopyError] = useState("");
	const data = project.recon;
	const assets = (data?.assets ?? []).filter(
		(a) =>
			a.value.includes(search.toLowerCase()) &&
			(filter === "all" || a.status === filter),
	);
	const pages = Math.max(1, Math.ceil(assets.length / 20));
	const currentPage = Math.min(page, pages - 1);
	async function copy(sections: "all" | "assets" | "evidence") {
		setCopying(true);
		setCopyMessage("");
		setCopyError("");
		try {
			const selected =
				sections === "assets" && data
					? { ...project, recon: { ...data, assets } }
					: project;
			await navigator.clipboard.writeText(
				redactText(reconMarkdown(selected, sections)),
			);
			setCopyMessage(
				sections === "all"
					? "Activos y evidencias del proyecto copiados en Markdown."
					: sections === "assets"
						? `${assets.length} activos copiados; se incluyen todos los resultados del filtro, no solo esta página.`
						: `${data?.evidence.length ?? 0} evidencias copiadas con sus datos y activos vinculados.`,
			);
		} catch (error) {
			recordFailure(project.id, {
				phase: "recon",
				stage: "Copiar hallazgos",
				error:
					error instanceof Error
						? error.message
						: "Portapapeles no disponible.",
			});
			setCopyError(
				"El navegador no permitió copiar. Puedes descargar el Informe Markdown desde la parte superior de Reconocimiento.",
			);
		} finally {
			setCopying(false);
		}
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-base">Hallazgos y evidencia</CardTitle>
				<CardDescription>
					Revisa procedencia y alcance antes de preparar la enumeración.
				</CardDescription>
			</CardHeader>
			<CardContent>
				<Tabs
					value={tab}
					onValueChange={(value) => {
						setTab(value);
						setCopyMessage("");
						setCopyError("");
					}}
				>
					<div className="mb-5 flex flex-wrap items-center justify-between gap-3">
						<TabsList className="h-auto flex-wrap">
							<TabsTrigger value="assets">
								Activos ({data?.assets.length ?? 0})
							</TabsTrigger>
							<TabsTrigger value="evidence">
								Evidencias ({data?.evidence.length ?? 0})
							</TabsTrigger>
						</TabsList>
						<div className="flex flex-wrap items-center gap-2">
							<Button
								size="sm"
								variant="outline"
								disabled={
									copying ||
									!(tab === "assets"
										? assets.length
										: data?.evidence.length ||
											project.checkHistory?.some((c) => c.phase === "recon") ||
											project.failures?.some((f) => f.phase === "recon"))
								}
								onClick={() =>
									void copy(tab === "assets" ? "assets" : "evidence")
								}
							>
								<Copy className="size-3.5" />
								{tab === "assets" ? "Copiar activos" : "Copiar evidencias"}
							</Button>
							<Button
								size="sm"
								variant="outline"
								disabled={
									copying ||
									!(
										data?.assets.length ||
										data?.evidence.length ||
										project.checkHistory?.some((c) => c.phase === "recon") ||
										project.failures?.some((f) => f.phase === "recon")
									)
								}
								onClick={() => void copy("all")}
							>
								<Copy className="size-3.5" />
								Copiar todo
							</Button>
							<fieldset
								aria-label="Vista de hallazgos"
								className="flex gap-1 rounded-md border p-1"
							>
								<Button
									size="icon-sm"
									variant={layout === "grid" ? "secondary" : "ghost"}
									aria-label="Vista de cuadrícula"
									title="Vista de cuadrícula"
									aria-pressed={layout === "grid"}
									onClick={() => setLayout("grid")}
								>
									<LayoutGrid className="size-4" />
								</Button>
								<Button
									size="icon-sm"
									variant={layout === "list" ? "secondary" : "ghost"}
									aria-label="Vista de lista"
									title="Vista de lista"
									aria-pressed={layout === "list"}
									onClick={() => setLayout("list")}
								>
									<List className="size-4" />
								</Button>
							</fieldset>
						</div>
					</div>
					{copyMessage && (
						<output className="mb-4 block text-xs text-success">
							{copyMessage}
						</output>
					)}
					{copyError && (
						<Alert variant="destructive" className="mb-4">
							<AlertDescription>{copyError}</AlertDescription>
						</Alert>
					)}
					<TabsContent value="assets" className="grid gap-4">
						<div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_230px]">
							<Input
								aria-label="Buscar activo candidato"
								placeholder="Buscar IP o nombre…"
								value={search}
								onChange={(event) => {
									setSearch(event.target.value);
									setPage(0);
								}}
							/>
							<Select
								value={filter}
								onValueChange={(value) => {
									setFilter(value);
									setPage(0);
								}}
							>
								<SelectTrigger aria-label="Filtrar revisión" className="w-full">
									<SelectValue />
								</SelectTrigger>
								<SelectContent>
									<SelectItem value="all">Todos los estados</SelectItem>
									{Object.entries(statuses).map(([key, value]) => (
										<SelectItem key={key} value={key}>
											{value}
										</SelectItem>
									))}
								</SelectContent>
							</Select>
						</div>
						{!assets.length && (
							<div className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">
								{data?.assets.length
									? "No hay activos que coincidan con el filtro."
									: "Recopila una fuente o carga activos manualmente para comenzar."}
							</div>
						)}
						<section
							className={
								layout === "grid" ? "grid gap-3 lg:grid-cols-2" : "grid gap-3"
							}
							aria-label="Activos candidatos"
						>
							{assets
								.slice(currentPage * 20, currentPage * 20 + 20)
								.map((asset) => {
									const scope = project.plan
										? targetDecision(asset.value, project.plan)
										: null;
									const issue = promotionIssue(project, asset);
									return (
										<article
											key={asset.id}
											className={`min-w-0 gap-3 rounded-xl border bg-background/40 p-4 ${layout === "grid" ? "flex flex-col" : "grid md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(160px,auto)] md:items-start"}`}
										>
											<div className="min-w-0">
												<h3 className="m-0 wrap-break-word font-mono text-sm font-medium">
													{asset.value}
												</h3>
												<div className="mt-2 flex flex-wrap gap-2">
													<Badge
														variant={
															asset.status === "reviewed"
																? "success"
																: asset.status === "candidate"
																	? "warning"
																	: "outline"
														}
													>
														{statuses[asset.status]}
													</Badge>
													<Badge
														variant={scope?.allowed ? "success" : "warning"}
													>
														{scope?.allowed
															? "Dentro del alcance definido"
															: "Requiere revisar alcance"}
													</Badge>
												</div>
											</div>
											<div className="grid min-w-0 gap-3">
												<p className="m-0 text-xs leading-relaxed text-muted-foreground">
													{scope?.reason ??
														"Completa el plan para comprobar este activo."}
												</p>
												<div className="text-xs text-muted-foreground">
													{asset.evidenceIds.length} fuente(s):{" "}
													{[
														...new Set(
															(data?.evidence ?? [])
																.filter((e) => asset.evidenceIds.includes(e.id))
																.map((e) => reconSources[e.source]),
														),
													].join(" · ")}
												</div>
												{asset.note && (
													<p className="m-0 max-h-24 overflow-y-auto whitespace-pre-wrap wrap-break-word text-xs">
														{asset.note}
													</p>
												)}
											</div>
											<div className="mt-auto grid gap-3">
												<div className="flex flex-wrap gap-2">
													<Button
														size="sm"
														variant="outline"
														disabled={busy}
														onClick={() => setEditing({ ...asset })}
													>
														<Pencil className="size-3.5" />
														Revisar
													</Button>
													<Button
														size="sm"
														disabled={busy || !!issue}
														title={
															issue || "Agregar como objetivo del proyecto"
														}
														onClick={() => onPromote(asset.id)}
													>
														<ArrowRight className="size-3.5" />A Enumeración
													</Button>
												</div>
												{issue && (
													<p className="m-0 text-[11px] leading-relaxed text-muted-foreground">
														{issue}
													</p>
												)}
											</div>
										</article>
									);
								})}
						</section>
						{assets.length > 20 && (
							<div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
								<span>
									Página {currentPage + 1} de {pages} · {assets.length} activos
								</span>
								<div className="flex gap-2">
									<Button
										size="sm"
										variant="outline"
										disabled={!currentPage}
										onClick={() => setPage(currentPage - 1)}
									>
										Anterior
									</Button>
									<Button
										size="sm"
										variant="outline"
										disabled={currentPage === pages - 1}
										onClick={() => setPage(currentPage + 1)}
									>
										Siguiente
									</Button>
								</div>
							</div>
						)}
						<p className="m-0 text-xs text-muted-foreground">
							Encontrar un subdominio, un proveedor o una dirección no amplía el
							alcance. Si corresponde incluirlo, modifica el acuerdo en{" "}
							<Link to="/alcance" className="text-primary underline">
								Alcance y planificación
							</Link>{" "}
							y registra una nueva aprobación.
						</p>
					</TabsContent>
					<TabsContent value="evidence" className="grid gap-3">
						{!data?.evidence.length && (
							<p className="text-sm text-muted-foreground">
								Aún no hay evidencia guardada.
							</p>
						)}
						<section
							className={
								layout === "grid"
									? "grid items-start gap-3 lg:grid-cols-2"
									: "grid gap-3"
							}
							aria-label="Evidencias guardadas"
						>
							{data?.evidence.map((evidence) => (
								<details
									key={evidence.id}
									className="min-w-0 rounded-xl border bg-background/40 p-4"
								>
									<summary className="cursor-pointer wrap-break-word text-sm font-medium">
										{evidence.query} · {reconSources[evidence.source]}
										<span className="mt-1 block text-xs font-normal text-muted-foreground">
											{new Date(evidence.retrievedAt).toLocaleString()} ·{" "}
											{evidence.scopeRevision
												? `plan r${evidence.scopeRevision}`
												: "sin revisión aprobada"}
										</span>
									</summary>
									<div className="mt-4 grid gap-4">
										<span className="wrap-break-word font-mono text-[11px] text-muted-foreground">
											ID: {evidence.id}
										</span>
										{evidence.executor && (
											<p className="m-0 break-all text-xs text-muted-foreground">
												Ejecutor SSH: {evidence.executor.username}@
												{evidence.executor.host}:{evidence.executor.port} ·{" "}
												{evidence.executor.fingerprint}
											</p>
										)}
										{evidence.sourceUrl && (
											<a
												className="flex min-w-0 items-start gap-2 text-xs text-primary underline"
												href={evidence.sourceUrl}
												target="_blank"
												rel="noopener noreferrer"
											>
												<ExternalLink className="size-3.5 shrink-0" />
												<span className="wrap-break-word">
													{evidence.sourceUrl}
												</span>
											</a>
										)}
										<dl className="grid gap-3">
											{[
												...new Map(
													evidence.facts.map((fact) => [
														`${fact.label}\u0000${fact.value}`,
														fact,
													]),
												).values(),
											].map((fact) => (
												<div
													key={`${fact.label}\u0000${fact.value}`}
													className="grid gap-1"
												>
													<dt className="text-xs font-medium">{fact.label}</dt>
													<dd className="m-0 whitespace-pre-wrap wrap-break-word text-xs text-muted-foreground">
														{fact.value}
													</dd>
												</div>
											))}
										</dl>
										{evidence.warnings.map((warning) => (
											<p
												className="m-0 text-xs text-muted-foreground"
												key={warning}
											>
												{warning}
											</p>
										))}
										{evidence.notes && (
											<p className="m-0 whitespace-pre-wrap wrap-break-word text-sm">
												{evidence.notes}
											</p>
										)}
										<div className="rounded-lg border p-3 text-xs">
											<span className="font-medium">
												Activos vinculados a esta evidencia
											</span>
											<p className="mb-0 mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap wrap-break-word font-mono">
												{data.assets
													.filter((a) => a.evidenceIds.includes(evidence.id))
													.map((a) => a.value)
													.join("\n") || "Sin activos; observación documental."}
											</p>
										</div>
										<Button
											className="w-fit"
											size="sm"
											variant="outline"
											disabled={busy}
											onClick={() => setDeleteId(evidence.id)}
										>
											<Trash2 className="size-3.5" />
											Eliminar evidencia
										</Button>
									</div>
								</details>
							))}
						</section>
					</TabsContent>
				</Tabs>
			</CardContent>
			<Dialog
				open={!!editing}
				onOpenChange={(open) => {
					if (!open) setEditing(null);
				}}
			>
				<DialogContent>
					<DialogHeader>
						<DialogTitle>Revisar activo candidato</DialogTitle>
						<DialogDescription className="wrap-break-word">
							{editing?.value}. Revisar documenta tu evaluación; su autorización
							depende del plan.
						</DialogDescription>
					</DialogHeader>
					{editing && (
						<>
							<div className="grid gap-2">
								<label
									htmlFor="recon-review-state"
									className="text-xs font-medium"
								>
									Estado de revisión
								</label>
								<Select
									value={editing.status}
									onValueChange={(status) =>
										setEditing({
											...editing,
											status: status as ReconAsset["status"],
										})
									}
								>
									<SelectTrigger id="recon-review-state" className="w-full">
										<SelectValue />
									</SelectTrigger>
									<SelectContent>
										{Object.entries(statuses).map(([key, label]) => (
											<SelectItem key={key} value={key}>
												{label}
											</SelectItem>
										))}
									</SelectContent>
								</Select>
							</div>
							<PlanField
								label="Notas de revisión"
								value={editing.note}
								multiline
								onChange={(note) => setEditing({ ...editing, note })}
								hint="Propiedad, terceros, confianza y razones para incluirlo o descartarlo."
							/>
							<DialogFooter>
								<Button variant="outline" onClick={() => setEditing(null)}>
									Cancelar
								</Button>
								<Button
									disabled={busy || editing.note.length > 4096}
									onClick={() => {
										onReview(editing.id, editing.status, editing.note);
										setEditing(null);
									}}
								>
									Guardar revisión
								</Button>
							</DialogFooter>
						</>
					)}
				</DialogContent>
			</Dialog>
			<Dialog
				open={!!deleteId}
				onOpenChange={(open) => {
					if (!open) setDeleteId("");
				}}
			>
				<DialogContent>
					<DialogHeader>
						<DialogTitle>Eliminar evidencia</DialogTitle>
						<DialogDescription>
							Se eliminará esta evidencia y los candidatos que no tengan otras
							fuentes. Los objetivos ya enviados a Enumeración se conservan.
							Exporta una copia antes si necesitas conservarla.
						</DialogDescription>
					</DialogHeader>
					<DialogFooter>
						<Button variant="outline" onClick={() => setDeleteId("")}>
							Cancelar
						</Button>
						<Button
							variant="destructive"
							disabled={busy}
							onClick={() => {
								onDelete(deleteId);
								setDeleteId("");
							}}
						>
							Eliminar evidencia
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>
		</Card>
	);
}
