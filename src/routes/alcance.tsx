import { createFileRoute } from "@tanstack/react-router";
import { PhasePage } from "#/components/PhasePage";
import { ScopePlanner } from "#/components/planning/ScopePlanner";

export const Route = createFileRoute("/alcance")({
	component: () => (
		<PhasePage
			title="Alcance y planificación"
			description="Registra la autorización, delimita los activos y acuerda las reglas antes de ejecutar."
		>
			<ScopePlanner />
		</PhasePage>
	),
});
