import { useRouterState } from "@tanstack/react-router";
import { AlertTriangle, LoaderCircle } from "lucide-react";
import { Button } from "./ui/button";
import { useWorkspace } from "./WorkspaceProvider";

export function ExecutionRequirementsNotice() {
	const pathname = useRouterState({
		select: (state) => state.location.pathname,
	});
	const {
		hydrated,
		ssh,
		kaliReady,
		kaliChecking,
		kaliError,
		kaliVerification,
		setKaliDialogOpen,
	} = useWorkspace();
	const module =
		pathname === "/enumeracion"
			? "Enumeración"
			: pathname === "/reconocimiento"
				? "Reconocimiento"
				: pathname === "/analisis"
					? "Análisis"
					: null;
	if (!hydrated || !module || kaliReady) return null;
	const configured = Boolean(
		ssh.host.trim() && ssh.username.trim() && ssh.privateKeyPath.trim(),
	);
	const title = kaliChecking
		? "Comprobando los requisitos de Kali…"
		: kaliError
			? "Kali no superó la comprobación"
			: !configured
				? "Configura Kali para ejecutar las pruebas"
				: kaliVerification
					? "La verificación de Kali caducó"
					: "Verifica Kali antes de ejecutar las pruebas";
	return (
		<section
			role={kaliChecking ? "status" : "alert"}
			aria-label={`Requisitos de ejecución · ${module}`}
			className="z-20 shrink-0 border-b border-warning-border bg-warning-surface px-4 py-3 text-foreground md:px-7"
		>
			<div className="mx-auto flex max-w-[1544px] flex-wrap items-start gap-3">
				{kaliChecking ? (
					<LoaderCircle className="mt-0.5 size-5 shrink-0 animate-spin text-warning" />
				) : (
					<AlertTriangle className="mt-0.5 size-5 shrink-0 text-warning" />
				)}
				<div className="min-w-0 flex-1 basis-60 space-y-1">
					<p className="m-0 text-sm font-semibold">
						{module} · {title}
					</p>
					<p className="m-0 text-xs leading-relaxed">
						Las acciones de red están bloqueadas. La ejecución local en esta PC
						está deshabilitada; necesitas un servidor Kali Linux por SSH, con
						Node.js 22 o superior y Nmap disponible.
					</p>
					{(module === "Reconocimiento" || module === "Análisis") && (
						<p className="m-0 text-xs">
							Puedes seguir revisando activos e importar evidencias manualmente.
						</p>
					)}
					{configured && !kaliChecking && !kaliError && (
						<p className="m-0 text-xs">
							La configuración guardada se comprueba automáticamente al cargar
							la página y la verificación se renueva al caducar. Si falta una
							huella aceptada o la frase de tu clave, completa la configuración.
						</p>
					)}
					{kaliError && (
						<details className="text-xs">
							<summary>Ver el error de la comprobación</summary>
							<p className="mt-2 max-h-24 overflow-y-auto whitespace-pre-wrap wrap-anywhere">
								{kaliError}
							</p>
						</details>
					)}
				</div>
				<Button
					size="sm"
					variant="outline"
					disabled={kaliChecking}
					onClick={() => setKaliDialogOpen(true)}
					className="border-warning-border bg-background"
				>
					{!configured
						? "Configurar Kali por SSH"
						: "Comprobar Kali y requisitos"}
				</Button>
			</div>
		</section>
	);
}
