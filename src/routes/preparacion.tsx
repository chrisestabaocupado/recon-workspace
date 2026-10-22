import { createFileRoute } from "@tanstack/react-router";
import { PhasePage } from "#/components/PhasePage";
import { PreparationGuide } from "#/components/PreparationGuide";

export const Route = createFileRoute("/preparacion")({
	head: () => ({
		meta: [{ title: "Preparación del entorno — Recon workspace" }],
	}),
	component: () => (
		<PhasePage
			title="Preparación del entorno"
			eyebrow="Antes de comenzar"
			description="Prepara Kali, conecta por SSH y comprueba los requisitos para reconocer y mapear activos."
		>
			<PreparationGuide />
		</PhasePage>
	),
});
