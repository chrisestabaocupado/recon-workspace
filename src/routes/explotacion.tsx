import { createFileRoute } from "@tanstack/react-router";
import { PhasePlaceholder } from "#/components/PhasePlaceholder";

export const Route = createFileRoute("/explotacion")({
	component: () => <PhasePlaceholder title="Explotación" />,
});
