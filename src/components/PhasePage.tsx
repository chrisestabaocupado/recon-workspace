import { Shield } from "lucide-react";
import type { ReactNode } from "react";
import { PhaseMobileNav, PhaseSidebar } from "#/components/PhaseSidebar";
import { ExecutionRequirementsNotice } from "./ExecutionRequirementsNotice";
import { KaliConnectionButton } from "./KaliConnection";
import { KaliTerminalButton } from "./KaliTerminal";

export function PhasePage({
	title,
	description,
	eyebrow = "Reconocimiento y mapeo",
	children,
}: {
	title: string;
	description: string;
	eyebrow?: string;
	children?: ReactNode;
}) {
	return (
		<div className="flex h-dvh flex-col overflow-hidden bg-background text-foreground">
			<header className="relative z-30 flex h-16 shrink-0 items-center gap-3 border-b bg-background/95 px-4 backdrop-blur md:px-7">
				<div className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-primary text-primary-foreground">
					<Shield className="size-5" />
				</div>
				<div className="min-w-0">
					<div className="truncate text-sm font-semibold tracking-tight">
						Recon workspace
					</div>
					<div className="hidden text-[11px] text-muted-foreground sm:block">
						Reconocimiento, mapeo e informes
					</div>
				</div>
				<div className="ml-auto flex shrink-0 items-center gap-2">
					<KaliTerminalButton />
					<KaliConnectionButton />
				</div>
			</header>
			<ExecutionRequirementsNotice />
			<div className="mx-auto flex min-h-0 w-full max-w-[1600px] flex-1 flex-col md:grid md:grid-cols-[280px_minmax(0,1fr)]">
				<PhaseMobileNav />
				<aside className="hidden min-h-0 min-w-0 overflow-y-auto overscroll-contain border-r bg-sidebar p-4 md:block">
					<PhaseSidebar />
				</aside>
				<main className="workspace-main">
					<div className="workspace-content">
						<div className="mb-7">
							<div className="mb-2 text-xs text-muted-foreground">
								{eyebrow}
							</div>
							<h1 className="text-2xl font-semibold tracking-tight md:text-[28px]">
								{title}
							</h1>
							<p className="mb-0 mt-1 text-sm text-muted-foreground">
								{description}
							</p>
						</div>
						{children}
					</div>
				</main>
			</div>
		</div>
	);
}
