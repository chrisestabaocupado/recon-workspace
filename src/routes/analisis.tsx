import { createFileRoute } from "@tanstack/react-router";
import { AnalysisWorkspace } from "#/components/analysis/AnalysisWorkspace";
import { PhasePage } from "#/components/PhasePage";

export const Route = createFileRoute("/analisis")({
	component: () => (
		<PhasePage
			title="Análisis de vulnerabilidades"
			description="Usa los servicios recolectados para buscar CVE en NVD, consultar bases locales y verificar vulnerabilidades desde Kali."
		>
			<AnalysisWorkspace />
		</PhasePage>
	),
});
