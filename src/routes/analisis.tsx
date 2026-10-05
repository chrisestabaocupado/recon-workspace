import { createFileRoute } from "@tanstack/react-router";
import { AnalysisWorkspace } from "#/components/analysis/AnalysisWorkspace";
import { PhasePage } from "#/components/PhasePage";

export const Route = createFileRoute("/analisis")({
	component: () => (
		<PhasePage
			title="Análisis de vulnerabilidades"
			description="Resume lo observado, consulta referencias locales y documenta verificaciones desde Kali."
		>
			<AnalysisWorkspace />
		</PhasePage>
	),
});
