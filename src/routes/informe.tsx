import { createFileRoute } from "@tanstack/react-router";
import { PhasePlaceholder } from "#/components/PhasePlaceholder";

export const Route = createFileRoute("/informe")({
	component: () => <PhasePlaceholder title="Informe" />,
});
