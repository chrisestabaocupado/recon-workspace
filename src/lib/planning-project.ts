import { type ScopePlan, validateScopePlan } from "./scope.ts";
import type { WorkspaceData } from "./storage.ts";

export function saveProjectPlan(
	workspace: WorkspaceData,
	projectId: string,
	name: string,
	value: ScopePlan,
): WorkspaceData {
	const plan = validateScopePlan(value);
	if (!name.trim() || name.length > 200)
		throw new Error("Nombre de proyecto inválido.");
	if (!workspace.projects.some((project) => project.id === projectId))
		throw new Error("El proyecto ya no existe.");
	return {
		...workspace,
		projects: workspace.projects.map((project) => {
			if (project.id !== projectId) return project;
			const previous = project.plan;
			const history =
				previous?.approvedAt && previous.revision !== plan.revision
					? [structuredClone(previous), ...(project.planHistory ?? [])].slice(
							0,
							10,
						)
					: (project.planHistory ?? []);
			return {
				...project,
				name: name.trim(),
				scope: plan.includes.join(", "),
				plan: structuredClone(plan),
				planHistory: history,
			};
		}),
	};
}
