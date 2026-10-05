import { useNavigate } from "@tanstack/react-router";
import { Plus } from "lucide-react";
import { useState } from "react";
import { newScopePlan } from "../lib/scope.ts";
import { validateWorkspace, type WorkspaceProject } from "../lib/storage.ts";
import { PlanField } from "./planning/PlanFields";
import { Alert, AlertDescription } from "./ui/alert";
import { Button } from "./ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "./ui/dialog";
import { useWorkspace } from "./WorkspaceProvider";

export function NewProjectButton({
	className,
	disabled = false,
	label = "Nuevo proyecto",
	variant = "default",
}: {
	className?: string;
	disabled?: boolean;
	label?: string;
	variant?: "default" | "outline";
}) {
	const { hydrated, projectCreationBlocked, setProjectDialogOpen } =
		useWorkspace();
	return (
		<Button
			className={className}
			variant={variant}
			disabled={!hydrated || projectCreationBlocked || disabled}
			onClick={() => setProjectDialogOpen(true)}
		>
			<Plus className="size-4" />
			{label}
		</Button>
	);
}

export function NewProjectDialog() {
	const navigate = useNavigate();
	const {
		workspace,
		setWorkspace,
		hydrated,
		projectDialogOpen,
		setProjectDialogOpen,
		projectCreationBlocked,
	} = useWorkspace();
	const [name, setName] = useState("");
	const [scope, setScope] = useState("");
	const [error, setError] = useState("");
	function close(open: boolean) {
		setProjectDialogOpen(open);
		if (!open) {
			setName("");
			setScope("");
			setError("");
		}
	}
	function create() {
		if (!hydrated || projectCreationBlocked || !name.trim()) return;
		try {
			const plan = newScopePlan();
			const project: WorkspaceProject = {
				id: crypto.randomUUID(),
				name: name.trim(),
				scope: scope.trim(),
				createdAt: new Date().toISOString(),
				targets: [],
				executions: 0,
				plan,
			};
			// Initial scope is descriptive, as in the existing enumeration form.
			// It remains pending review in the draft plan.
			if (project.scope)
				plan.notes = `Alcance inicial pendiente de revisión: ${project.scope}`;
			validateWorkspace({
				...workspace,
				projects: [project, ...workspace.projects],
				selectedProjectId: project.id,
			});
			setWorkspace((current) => ({
				...current,
				projects: [project, ...current.projects],
				selectedProjectId: project.id,
			}));
			close(false);
			void navigate({ to: "/alcance" });
		} catch (e) {
			setError(
				e instanceof Error ? e.message : "No se pudo crear el proyecto.",
			);
		}
	}
	return (
		<Dialog open={projectDialogOpen} onOpenChange={close}>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>Nuevo proyecto</DialogTitle>
					<DialogDescription>
						Se crea como borrador. Revisa y aprueba su alcance antes de ejecutar
						pruebas.
					</DialogDescription>
				</DialogHeader>
				<form
					onSubmit={(event) => {
						event.preventDefault();
						create();
					}}
					className="grid gap-4"
				>
					<PlanField
						label="Nombre del proyecto"
						value={name}
						onChange={setName}
						placeholder="Auditoría interna"
					/>
					<PlanField
						label="Alcance inicial (pendiente de aprobación)"
						value={scope}
						onChange={setScope}
						multiline
						placeholder="192.168.1.0/24, app.empresa.test"
					/>
					{error && (
						<Alert variant="destructive">
							<AlertDescription>{error}</AlertDescription>
						</Alert>
					)}
					<DialogFooter>
						<Button
							type="button"
							variant="outline"
							onClick={() => close(false)}
						>
							Cancelar
						</Button>
						<Button
							type="submit"
							disabled={
								!hydrated ||
								projectCreationBlocked ||
								!name.trim() ||
								name.trim().length > 200
							}
						>
							Crear proyecto
						</Button>
					</DialogFooter>
				</form>
			</DialogContent>
		</Dialog>
	);
}
