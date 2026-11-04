import { createFileRoute, Link } from "@tanstack/react-router";
import {
	ArrowDownToLine,
	ArrowRight,
	ArrowUpFromLine,
	FolderKanban,
	LoaderCircle,
	Search,
	Shield,
	Wrench,
} from "lucide-react";
import { useRef, useState } from "react";
import { KaliConnectionButton } from "#/components/KaliConnection";
import { KaliTerminalButton } from "#/components/KaliTerminal";
import { phases } from "#/components/PhaseSidebar";
import { NewProjectButton } from "#/components/ProjectCreation";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "#/components/ui/card";
import { Input } from "#/components/ui/input";
import { useWorkspace } from "#/components/WorkspaceProvider";
import { exportWorkspace, importWorkspace } from "#/lib/storage";

export const Route = createFileRoute("/")({ component: ProjectDashboard });

const statusLabels = {
	draft: "Borrador",
	approved: "Alcance aprobado",
	paused: "Pausado",
	closed: "Cerrado",
};

function ProjectDashboard() {
	const { workspace, setWorkspace, hydrated, storageError, replaceWorkspace } =
		useWorkspace();
	const [search, setSearch] = useState("");
	const [fileError, setFileError] = useState("");
	const fileInput = useRef<HTMLInputElement>(null);
	const projects = workspace.projects.filter((project) =>
		`${project.name} ${project.scope}`
			.toLocaleLowerCase()
			.includes(search.trim().toLocaleLowerCase()),
	);
	function selectProject(id: string) {
		setWorkspace((current) => ({ ...current, selectedProjectId: id }));
	}
	function saveExport() {
		try {
			const url = URL.createObjectURL(
				new Blob([exportWorkspace(workspace)], { type: "application/json" }),
			);
			const anchor = document.createElement("a");
			anchor.href = url;
			anchor.download = "one-two-three-workspace.json";
			anchor.click();
			URL.revokeObjectURL(url);
			setFileError("");
		} catch (error) {
			setFileError(
				error instanceof Error ? error.message : "No se pudo exportar.",
			);
		}
	}
	async function importFile(file?: File) {
		if (!file) return;
		try {
			if (file.size > 5 * 1024 * 1024)
				throw new Error("La importación supera 5 MB.");
			replaceWorkspace(importWorkspace(await file.text()));
			setFileError("");
		} catch (error) {
			setFileError(
				error instanceof Error
					? error.message
					: "No se pudo importar el archivo.",
			);
		} finally {
			if (fileInput.current) fileInput.current.value = "";
		}
	}
	return (
		<div className="min-h-dvh bg-background text-foreground">
			<header className="border-b bg-background/95 px-4 py-4 md:px-7">
				<div className="mx-auto flex max-w-[1480px] flex-wrap items-center justify-between gap-4">
					<Link to="/" className="flex items-center gap-3">
						<div className="flex size-9 items-center justify-center rounded-xl bg-primary text-primary-foreground">
							<Shield className="size-5" />
						</div>
						<div>
							<div className="text-sm font-semibold">Recon workspace</div>
							<div className="text-[11px] text-muted-foreground">
								Dashboard de proyectos
							</div>
						</div>
					</Link>
					<div className="flex flex-wrap items-center gap-2">
						<KaliTerminalButton />
						<KaliConnectionButton />
						<Button
							variant="outline"
							size="sm"
							disabled={!hydrated}
							onClick={saveExport}
						>
							<ArrowDownToLine className="size-4" />
							Exportar
						</Button>
						<Button
							variant="outline"
							size="sm"
							disabled={!hydrated}
							onClick={() => fileInput.current?.click()}
						>
							<ArrowUpFromLine className="size-4" />
							Importar
						</Button>
						<input
							ref={fileInput}
							type="file"
							accept="application/json,.json"
							aria-label="Importar proyectos"
							className="hidden"
							onChange={(event) => void importFile(event.target.files?.[0])}
						/>
					</div>
				</div>
			</header>
			<main className="mx-auto max-w-[1480px] px-4 py-8 md:px-7 md:py-12">
				<div className="mb-8 flex flex-wrap items-end justify-between gap-4">
					<div>
						<p className="mb-2 text-xs text-muted-foreground">
							Workspace / Proyectos
						</p>
						<h1 className="text-3xl font-semibold tracking-tight">
							Tus proyectos
						</h1>
						<p className="mb-0 mt-2 text-sm text-muted-foreground">
							Organiza el alcance, reconoce activos y mapea hosts y servicios
							para generar tus informes.
						</p>
					</div>
					<NewProjectButton />
				</div>
				{(storageError || fileError) && (
					<Alert variant="destructive" className="mb-6">
						<AlertDescription>{fileError || storageError}</AlertDescription>
					</Alert>
				)}
				<div className="mb-8 grid gap-3 sm:grid-cols-3">
					{[
						["Proyectos", workspace.projects.length],
						[
							"Con alcance aprobado",
							workspace.projects.filter(
								(project) => project.plan?.status === "approved",
							).length,
						],
						[
							"Ejecuciones registradas",
							workspace.projects.reduce(
								(total, project) => total + project.executions,
								0,
							),
						],
					].map(([label, count]) => (
						<Card key={label} className="gap-2 py-4">
							<CardContent>
								<p className="m-0 text-xs text-muted-foreground">{label}</p>
								<p className="mb-0 mt-2 text-2xl font-semibold">
									{hydrated ? count : "—"}
								</p>
							</CardContent>
						</Card>
					))}
				</div>
				<div className="mb-5 flex flex-wrap items-center justify-between gap-4">
					<h2 className="text-lg font-semibold">Proyectos creados</h2>
					<div className="relative w-full sm:w-80">
						<Search className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
						<Input
							aria-label="Buscar proyectos"
							placeholder="Buscar por nombre o alcance…"
							className="pl-9"
							value={search}
							onChange={(event) => setSearch(event.target.value)}
						/>
					</div>
				</div>
				{!hydrated ? (
					<output className="flex items-center gap-2 py-12 text-sm text-muted-foreground">
						<LoaderCircle className="size-4 animate-spin" />
						Cargando proyectos…
					</output>
				) : projects.length ? (
					<div className="grid gap-5 lg:grid-cols-2 xl:grid-cols-3">
						{projects.map((project) => (
							<Card key={project.id} className="min-w-0 gap-4">
								<CardHeader>
									<div className="mb-3 flex items-center justify-between gap-2">
										<FolderKanban className="size-5 text-muted-foreground" />
										<Badge
											variant={
												project.plan?.status === "approved"
													? "success"
													: "outline"
											}
										>
											{statusLabels[project.plan?.status ?? "draft"]}
										</Badge>
									</div>
									<CardTitle className="break-words text-lg">
										{project.name}
									</CardTitle>
									<p className="m-0 line-clamp-2 break-words text-xs leading-relaxed text-muted-foreground">
										{project.scope || "Alcance pendiente de definir"}
									</p>
									<p className="m-0 text-xs text-muted-foreground">
										{project.targets.length} objetivos · {project.executions}{" "}
										ejecuciones · {project.recon?.assets.length ?? 0} activos
										descubiertos
									</p>
								</CardHeader>
								<CardContent className="grid gap-4">
									<Button asChild className="w-full">
										<Link
											to="/alcance"
											onClick={() => selectProject(project.id)}
										>
											Abrir proyecto
											<ArrowRight className="size-4" />
										</Link>
									</Button>
									<nav
										aria-label={`Fases de ${project.name}`}
										className="grid gap-1 border-t pt-3"
									>
										{phases.map(({ to, label, icon: Icon, status }, index) => (
											<Link
												key={to}
												to={to}
												onClick={() => selectProject(project.id)}
												className="flex items-center gap-2 rounded-md px-2 py-2 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
											>
												<span className="w-3 text-[10px]">{index + 1}</span>
												<Icon className="size-3.5 shrink-0" />
												<span className="flex-1">{label}</span>
												{status && (
													<span className="text-[10px]">{status}</span>
												)}
												<ArrowRight className="size-3" />
											</Link>
										))}
									</nav>
								</CardContent>
							</Card>
						))}
					</div>
				) : (
					<div className="rounded-xl border border-dashed px-6 py-16 text-center">
						<FolderKanban className="mx-auto mb-4 size-10 text-muted-foreground" />
						<h2 className="text-lg font-semibold">
							{workspace.projects.length
								? "No hay proyectos que coincidan"
								: "Crea tu primer proyecto"}
						</h2>
						<p className="mt-2 text-sm text-muted-foreground">
							{workspace.projects.length
								? "Prueba con otro nombre o alcance."
								: "Empieza por definir el alcance y reúne el trabajo de cada fase en un solo lugar."}
						</p>
						{workspace.projects.length ? (
							<Button variant="outline" onClick={() => setSearch("")}>
								Limpiar búsqueda
							</Button>
						) : (
							<NewProjectButton />
						)}
					</div>
				)}
				<footer className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t pt-5 text-xs text-muted-foreground">
					<span>
						Datos guardados localmente en este navegador. Exporta una copia para
						conservarlos.
					</span>
					<Link
						to="/preparacion"
						className="flex items-center gap-2 hover:text-foreground"
					>
						<Wrench className="size-3.5" />
						Preparación del entorno
					</Link>
				</footer>
			</main>
		</div>
	);
}
