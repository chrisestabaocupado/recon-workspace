import { createFileRoute } from "@tanstack/react-router";
import { PhasePlaceholder } from "#/components/PhasePlaceholder";

export const Route = createFileRoute("/post-explotacion")({
	component: () => <PhasePlaceholder title="Post-explotación" />,
});
