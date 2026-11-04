import { createFileRoute } from "@tanstack/react-router";
import { PhasePage } from "#/components/PhasePage";
import { ReconWorkspace } from "#/components/recon/ReconWorkspace";

export const Route = createFileRoute("/reconocimiento")({
	component: () => (
		<PhasePage
			title="Reconocimiento"
			description="Consulta dominios o IP autorizadas, documenta activos y revisa su alcance antes de enumerar."
		>
			<ReconWorkspace />
		</PhasePage>
	),
});
