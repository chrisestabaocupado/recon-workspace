import { Link, useRouterState } from "@tanstack/react-router";
import {
	Activity,
	BookOpenCheck,
	Crosshair,
	FileText,
	LayoutDashboard,
	Radar,
	ScanSearch,
	ShieldAlert,
	Wrench,
} from "lucide-react";
import { Badge } from "#/components/ui/badge";
import { NewProjectButton } from "./ProjectCreation";
import { useWorkspace } from "./WorkspaceProvider";

export const phases = [
	{
		to: "/alcance",
		label: "Alcance y planificación",
		icon: BookOpenCheck,
		status: null,
	},
	{
		to: "/reconocimiento",
		label: "Reconocimiento",
		icon: Radar,
		status: null,
	},
	{ to: "/enumeracion", label: "Enumeración", icon: ScanSearch, status: null },
	{
		to: "/analisis",
		label: "Análisis de vulnerabilidades",
		icon: ShieldAlert,
		status: null,
	},
	{
		to: "/explotacion",
		label: "Explotación",
		icon: Crosshair,
		status: "Pendiente",
	},
	{
		to: "/post-explotacion",
		label: "Post-explotación",
		icon: Activity,
		status: "Pendiente",
	},
	{ to: "/informe", label: "Informe", icon: FileText, status: "Pendiente" },
] as const;

export function PhaseSidebar() {
	const { workspace } = useWorkspace();
	const project = workspace.projects.find(
		(item) => item.id === workspace.selectedProjectId,
	);
	const pathname = useRouterState({
		select: (state) => state.location.pathname,
	});

	return (
		<div className="min-w-0">
			<Link
				to="/"
				className="mb-4 flex items-center gap-3 rounded-md px-3 py-3 text-sm text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
			>
				<LayoutDashboard className="size-4" /> Proyectos
			</Link>
			<NewProjectButton className="mb-6 w-full justify-start" />
			<Link
				to="/preparacion"
				aria-current={pathname === "/preparacion" ? "page" : undefined}
				className={`mb-6 flex items-center gap-3 rounded-md px-3 py-3 text-sm transition-colors ${pathname === "/preparacion" ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground" : "text-sidebar-foreground/75 hover:bg-sidebar-accent/70 hover:text-sidebar-foreground"}`}
			>
				<Wrench className="size-4 shrink-0" />
				Preparación del entorno
			</Link>
			<div className="mb-3 px-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
				Fases del pentesting
			</div>
			{project && (
				<div className="mb-3 break-words px-2 text-sm font-medium">
					{project.name}
				</div>
			)}
			<nav
				aria-label="Fases del pentesting"
				className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-1"
			>
				{phases.map(({ to, label, icon: Icon, status }, index) => {
					const active = pathname === to;
					return (
						<Link
							key={to}
							to={to}
							aria-current={active ? "page" : undefined}
							className={`grid min-h-14 min-w-0 grid-cols-[1.5rem_1rem_minmax(0,1fr)_0.375rem] items-center gap-x-2 gap-y-1 rounded-md px-2.5 py-2.5 text-sm transition-colors ${active ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground" : "text-sidebar-foreground/75 hover:bg-sidebar-accent/70 hover:text-sidebar-foreground"}`}
						>
							<span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-background/70 text-[10px] text-muted-foreground">
								{index + 1}
							</span>
							<Icon className="size-4 shrink-0" />
							<span className="min-w-0 wrap-break-word leading-snug">
								{label}
							</span>
							{active ? (
								<span
									className="size-1.5 shrink-0 rounded-full bg-primary"
									aria-hidden="true"
								/>
							) : null}
							{status && (
								<Badge
									variant="outline"
									className="col-start-3 col-end-5 row-start-2 max-w-full px-1.5 py-0 text-[10px] font-normal text-muted-foreground"
								>
									{status}
								</Badge>
							)}
						</Link>
					);
				})}
			</nav>
			<div className="mt-8 rounded-xl border bg-card p-3">
				<div className="text-xs font-medium">Datos locales</div>
				<p className="mb-0 mt-1.5 text-[11px] leading-relaxed text-muted-foreground">
					Los proyectos viven en este navegador. Exporta una copia para moverlos
					a Kali.
				</p>
			</div>
		</div>
	);
}

export function PhaseMobileNav() {
	const pathname = useRouterState({
		select: (state) => state.location.pathname,
	});

	return (
		<nav
			aria-label="Fases del pentesting"
			className="flex min-w-0 max-w-full shrink-0 gap-1 overflow-x-auto border-b bg-background px-3 py-2 md:hidden"
		>
			<Link
				to="/"
				className="shrink-0 rounded-md px-2.5 py-2 text-xs text-muted-foreground hover:bg-muted"
			>
				Proyectos
			</Link>
			<NewProjectButton className="shrink-0 text-xs" />
			<Link
				to="/preparacion"
				aria-current={pathname === "/preparacion" ? "page" : undefined}
				className={`shrink-0 rounded-md px-2.5 py-2 text-xs transition-colors ${pathname === "/preparacion" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted"}`}
			>
				Preparación
			</Link>
			{phases.map(({ to }, index) => {
				const active = pathname === to;
				const shortLabel = [
					"Alcance",
					"Reconocimiento",
					"Enumeración",
					"Análisis",
					"Explotación",
					"Post",
					"Informe",
				][index];
				return (
					<Link
						key={to}
						to={to}
						aria-current={active ? "page" : undefined}
						className={`shrink-0 rounded-md px-2.5 py-2 text-xs transition-colors ${active ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted"}`}
					>
						{shortLabel}
					</Link>
				);
			})}
		</nav>
	);
}
