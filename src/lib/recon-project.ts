import { failuresMarkdown } from "./operation-history.ts";
import {
	mergeReconResult,
	type ReconAsset,
	type ReconData,
	type ReconResult,
	removeReconEvidence,
	validateReconData,
} from "./recon.ts";
import {
	approvalIssues,
	normalizeScopeEntry,
	targetDecision,
} from "./scope.ts";
import type { WorkspaceData, WorkspaceProject } from "./storage.ts";
import {
	appendCheckHistory,
	checklistMarkdown,
	evidenceCheck,
} from "./test-checklist.ts";

function changeProject(
	workspace: WorkspaceData,
	id: string,
	update: (project: WorkspaceProject) => WorkspaceProject,
): WorkspaceData {
	if (!workspace.projects.some((p) => p.id === id))
		throw new Error("El proyecto de la consulta ya no existe.");
	return {
		...workspace,
		projects: workspace.projects.map((p) => (p.id === id ? update(p) : p)),
	};
}
export function saveReconResult(
	workspace: WorkspaceData,
	id: string,
	result: ReconResult,
	notes = "",
	newId?: () => string,
): WorkspaceData {
	return changeProject(workspace, id, (project) => {
		const recon = mergeReconResult(project.recon, result, notes, newId);
		return {
			...project,
			recon,
			checkHistory: appendCheckHistory(
				project.checkHistory,
				evidenceCheck(recon.evidence[0]),
			),
		};
	});
}
export function editReconAsset(
	workspace: WorkspaceData,
	projectId: string,
	assetId: string,
	status: ReconAsset["status"],
	note: string,
	now = Date.now(),
): WorkspaceData {
	return changeProject(workspace, projectId, (p) => {
		if (!p.recon?.assets.some((a) => a.id === assetId))
			throw new Error("El activo ya no existe.");
		const recon = validateReconData({
			...p.recon,
			assets: p.recon.assets.map((a) =>
				a.id === assetId
					? { ...a, status, note, updatedAt: new Date(now).toISOString() }
					: a,
			),
		});
		return { ...p, recon };
	});
}
export function deleteReconEvidence(
	workspace: WorkspaceData,
	projectId: string,
	evidenceId: string,
): WorkspaceData {
	return changeProject(workspace, projectId, (p) => ({
		...p,
		recon: p.recon ? removeReconEvidence(p.recon, evidenceId) : undefined,
	}));
}
export function promotionIssue(
	project: WorkspaceProject,
	asset: ReconAsset,
	now = Date.now(),
): string {
	if (asset.status !== "reviewed")
		return "Revisa el activo antes de enviarlo a Enumeración.";
	if (!project.plan || project.plan.status !== "approved")
		return "El plan debe estar aprobado.";
	const issues = approvalIssues(project.plan, now);
	if (issues.length) return issues[0];
	const decision = targetDecision(asset.value, project.plan);
	if (!decision.allowed) return decision.reason;
	if (
		project.targets.some((t) => {
			try {
				return normalizeScopeEntry(t.value) === asset.value;
			} catch {
				return false;
			}
		})
	)
		return "Este activo ya está en los objetivos de Enumeración.";
	if (project.targets.length >= 10000)
		return "El proyecto alcanzó el límite de objetivos.";
	return "";
}
export function promoteReconAsset(
	workspace: WorkspaceData,
	projectId: string,
	assetId: string,
	now = Date.now(),
	newId: () => string = () => crypto.randomUUID(),
): WorkspaceData {
	return changeProject(workspace, projectId, (p) => {
		const asset = p.recon?.assets.find((a) => a.id === assetId);
		if (!asset) throw new Error("El activo ya no existe.");
		const issue = promotionIssue(p, asset, now);
		if (issue) throw new Error(issue);
		return {
			...p,
			targets: [
				...p.targets,
				{
					id: newId(),
					value: asset.value,
					note: `Reconocimiento · plan r${p.plan?.revision} · evidencias ${asset.evidenceIds.join(", ")}\n${asset.note}`.slice(
						0,
						4096,
					),
				},
			],
		};
	});
}
export function reconMarkdown(
	project: WorkspaceProject,
	sections: "all" | "assets" | "evidence" = "all",
): string {
	const data: ReconData = project.recon ?? {
		version: 1,
		evidence: [],
		assets: [],
	};
	const literal = (s: string) => s.replace(/[\\`*_{}[\]<>#|]/g, "\\$&");
	return [
		`# Reconocimiento — ${literal(project.name)}`,
		"",
		`Exportado: ${new Date().toISOString()}`,
		`Plan: ${project.plan ? `r${project.plan.revision} · ${project.plan.status}` : "sin plan"}`,
		`Incluidos: ${project.plan?.includes.map(literal).join(", ") || "sin definir"}`,
		`Excluidos: ${project.plan?.excludes.map(literal).join(", ") || "ninguno registrado"}`,
		"",
		...(sections !== "evidence"
			? [
					"## Activos candidatos",
					"",
					...data.assets.flatMap((a) => [
						`- ${literal(a.value)} · ${a.status} · fuentes: ${a.evidenceIds.join(", ")}`,
						`  ${literal(a.note)}`,
						`  Alcance: ${literal(project.plan ? targetDecision(a.value, project.plan).reason : "Sin plan definido")}`,
						`  Fuentes: ${data.evidence
							.filter((e) => a.evidenceIds.includes(e.id))
							.map((e) => e.source)
							.join(", ")}`,
					]),
					"",
				]
			: []),
		...(sections !== "assets"
			? [
					"## Evidencias",
					"",
					...data.evidence.flatMap((e) => [
						`### ${literal(e.query)} · ${e.source}`,
						"",
						`ID: ${e.id}; fecha: ${e.retrievedAt}; plan: ${e.scopeRevision ? `r${e.scopeRevision}` : "sin revisión aprobada"}`,
						`Fuente: ${literal(e.sourceUrl || (e.source === "dns" ? "Resolvedores DNS de Kali" : "Registro manual"))}`,
						`Activos vinculados: ${
							data.assets
								.filter((a) => a.evidenceIds.includes(e.id))
								.map((a) => literal(a.value))
								.join(", ") || "sin activos"
						}`,
						...(e.executor
							? [
									`Ejecutor SSH: ${literal(`${e.executor.username}@${e.executor.host}:${e.executor.port}`)}; huella: ${literal(e.executor.fingerprint)}`,
								]
							: []),
						"",
						...e.facts.map((f) => `- ${literal(f.label)}: ${literal(f.value)}`),
						...e.warnings.map((w) => `- Aviso: ${literal(w)}`),
						"",
						literal(e.notes),
						"",
					]),
				]
			: []),
		...(sections !== "assets"
			? [
					checklistMarkdown(project, "recon"),
					failuresMarkdown(
						(project.failures ?? []).filter((f) => f.phase === "recon"),
					),
					"",
				]
			: []),
		"Los candidatos requieren revisión y pertenencia al plan aprobado antes de enumerar.",
	].join("\n");
}
