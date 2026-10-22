import { createFileRoute } from "@tanstack/react-router";
import { PhasePage } from "#/components/PhasePage";
import { ReportWorkspace } from "#/components/reports/ReportWorkspace";

export const Route = createFileRoute("/informe")({
	head: () => ({ meta: [{ title: "Informes — Recon workspace" }] }),
	component: () => (
		<PhasePage
			title="Informes"
			description="Consolida el alcance, los activos, los hosts y los servicios observados. Revisa el informe y expórtalo en Markdown o PDF."
		>
			<ReportWorkspace />
		</PhasePage>
	),
});
