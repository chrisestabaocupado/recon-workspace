import { createFileRoute } from "@tanstack/react-router";
import { PhasePage } from "#/components/PhasePage";
import { PreparationGuide } from "#/components/PreparationGuide";

export const Route = createFileRoute("/preparacion")({
	head: () => ({
		meta: [{ title: "Preparación del entorno — Pentest workspace" }],
	}),
	component: () => (
		<PhasePage
			title="Preparación del entorno"
			eyebrow="Antes de comenzar"
			description="Prepara Kali, conecta por SSH y comprueba los requisitos antes de pasar a las fases del pentesting."
		>
			<PreparationGuide />
		</PhasePage>
	),
});
