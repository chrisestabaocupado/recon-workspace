import { createRootRoute, HeadContent, Scripts } from "@tanstack/react-router";
import { WorkspaceProvider } from "#/components/WorkspaceProvider";
import appCss from "../styles.css?url";

export const Route = createRootRoute({
	head: () => ({
		meta: [
			{
				charSet: "utf-8",
			},
			{
				name: "viewport",
				content: "width=device-width, initial-scale=1",
			},
			{
				title: "Reconocimiento y mapeo — recon-workspace",
			},
		],
		links: [
			{
				rel: "stylesheet",
				href: appCss,
			},
		],
	}),
	shellComponent: RootDocument,
});

function RootDocument({ children }: { children: React.ReactNode }) {
	return (
		<html lang="es" className="dark" style={{ colorScheme: "dark" }}>
			<head>
				<HeadContent />
			</head>
			<body className="font-sans antialiased">
				<WorkspaceProvider>{children}</WorkspaceProvider>
				<Scripts />
			</body>
		</html>
	);
}
