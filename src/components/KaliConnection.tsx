import { LoaderCircle, Server, ShieldCheck } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { isActiveJob } from "#/lib/execution";
import { type KaliToolCheck, kaliToolHelp } from "#/lib/kali";
import {
	type InstallableTool,
	installableTools,
	type KaliInstallView,
	missingInstallableTools,
} from "#/lib/kali-install";
import {
	getKaliInstallation,
	startKaliInstallation,
} from "#/server/kali-install";
import { PlanField } from "./planning/PlanFields";
import { Alert, AlertDescription } from "./ui/alert";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "./ui/card";
import { Checkbox } from "./ui/checkbox";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "./ui/dialog";
import { useWorkspace } from "./WorkspaceProvider";

function KaliToolsStatus({ tools }: { tools: KaliToolCheck[] }) {
	const unavailable = tools.filter((tool) => !tool.available);
	return (
		<section
			className="space-y-3 rounded-lg border p-3"
			aria-label="Herramientas comprobadas en Kali"
		>
			<h3 className="text-sm font-medium">Herramientas de análisis</h3>
			<p
				className={`text-xs ${unavailable.length ? "text-warning" : "text-success"}`}
			>
				{unavailable.length
					? `${unavailable.length} herramientas no disponibles. SSH está verificado; las acciones que requieren esas herramientas están bloqueadas.`
					: "Herramientas comprobadas. Revisa también sus bases y la conectividad de las fuentes."}
			</p>
			{tools.map((tool) => {
				const help = kaliToolHelp[tool.tool];
				return (
					<details
						key={tool.tool}
						open={!tool.available}
						className="rounded border p-3 text-xs"
					>
						<summary className="cursor-pointer font-medium">
							{help.label} ·{" "}
							<span
								className={tool.available ? "text-success" : "text-warning"}
							>
								{tool.tool === "nvd"
									? "Sin instalación"
									: tool.tool === "cve" && !tool.available
										? "API local no disponible"
										: tool.status === "available"
											? "Disponible"
											: tool.status === "missing"
												? "No instalado / fuera de PATH"
												: "Comprobación fallida"}
							</span>
						</summary>
						<p className="mt-2 whitespace-pre-wrap break-words">
							{tool.detail}
						</p>
						<p className="mt-2 text-muted-foreground">{tool.database}</p>
						{!tool.available && help.command && (
							<>
								<p className="mt-2">Ejecuta en Kali:</p>
								<code className="mt-1 block select-all rounded bg-muted p-2">
									{help.command}
								</code>
							</>
						)}
						{!tool.available && (
							<a
								href={help.url}
								target="_blank"
								rel="noreferrer"
								className="mt-2 inline-block underline"
							>
								Preparación oficial de {help.label}
							</a>
						)}
					</details>
				);
			})}
			<p className="text-xs text-muted-foreground">
				Después de instalar o configurar, pulsa «Comprobar SSH y herramientas»
				para actualizar el estado.
			</p>
		</section>
	);
}

export function KaliConnectionButton() {
	const {
		kaliReady,
		kaliChecking,
		kaliError,
		kaliVerification,
		setKaliDialogOpen,
		kaliInstalling,
	} = useWorkspace();
	const missingTools = kaliReady
		? (kaliVerification?.tools?.filter((t) => !t.available).length ?? 0)
		: 0;
	return (
		<Button
			variant="outline"
			size="sm"
			aria-label="Configurar Kali por SSH"
			onClick={() => setKaliDialogOpen(true)}
		>
			{kaliChecking ? (
				<LoaderCircle className="size-4 animate-spin" />
			) : kaliReady ? (
				<ShieldCheck
					className={`size-4 ${missingTools ? "text-warning" : "text-success"}`}
				/>
			) : (
				<Server className="size-4" />
			)}
			<span>
				{kaliInstalling
					? "Instalando en Kali…"
					: kaliChecking
						? "Comprobando Kali…"
						: kaliReady
							? missingTools
								? `Kali · ${missingTools} herramientas pendientes`
								: "Kali verificado"
							: kaliError
								? "Revisar conexión Kali"
								: "Configurar Kali"}
			</span>
			{kaliReady && (
				<span className="hidden max-w-40 truncate text-xs text-muted-foreground xl:inline">
					{kaliVerification?.executor.host}
				</span>
			)}
		</Button>
	);
}

export function KaliExecutionCard() {
	const { kaliReady, kaliVerification, setKaliDialogOpen } = useWorkspace();
	return (
		<Card>
			<CardHeader>
				<CardTitle className="flex items-center gap-2 text-sm">
					<Server className="size-4 text-primary" />
					Ejecutor global · Kali
				</CardTitle>
				<CardDescription>
					Todas las pruebas y consultas de red se ejecutan en Kali por SSH.
				</CardDescription>
			</CardHeader>
			<CardContent className="space-y-4">
				<Badge variant={kaliReady ? "success" : "warning"}>
					{kaliReady ? "SSH verificado" : "Verificación pendiente"}
				</Badge>
				{kaliReady && kaliVerification ? (
					<div className="space-y-2 text-sm">
						<p className="break-all">
							{kaliVerification.executor.username}@
							{kaliVerification.executor.host}:{kaliVerification.executor.port}
						</p>
						<p className="text-xs text-muted-foreground">
							{kaliVerification.version}
						</p>
					</div>
				) : (
					<p className="text-sm text-muted-foreground">
						Configura el servidor desde el navbar. La misma conexión se utiliza
						en todas las fases.
					</p>
				)}
				<Button variant="outline" onClick={() => setKaliDialogOpen(true)}>
					{kaliReady ? "Ver configuración SSH" : "Configurar Kali por SSH"}
				</Button>
				<p className="text-xs text-muted-foreground">
					Cada operación abre su sesión SSH con la huella verificada. Si Kali no
					está disponible, la operación falla.
				</p>
			</CardContent>
		</Card>
	);
}

export function KaliConnectionDialog() {
	const {
		ssh,
		setSsh,
		sshPassphrase,
		setSshPassphrase,
		kaliDialogOpen,
		setKaliDialogOpen,
		kaliChecking,
		kaliReady,
		kaliVerification,
		kaliError,
		observedKaliFingerprint,
		verifyKali,
		acceptKaliFingerprint,
		getKaliAccess,
		kaliInstalling,
		setKaliInstalling,
		projectCreationBlocked,
		execution,
		startingRequest,
		workspace,
		recordFailure,
	} = useWorkspace();
	const [trustedFingerprint, setTrustedFingerprint] = useState("");
	const [sudoPassword, setSudoPassword] = useState("");
	const [selectedTools, setSelectedTools] = useState<InstallableTool[]>([]);
	const [installation, setInstallation] = useState<KaliInstallView>();
	const [installError, setInstallError] = useState("");
	const [installTarget, setInstallTarget] = useState("");
	const tools = kaliVerification?.tools ?? [];
	const missing = missingInstallableTools(tools);
	const connectionBusy = kaliChecking || kaliInstalling;
	const operationBusy =
		projectCreationBlocked ||
		startingRequest ||
		Boolean(execution && isActiveJob(execution.state)) ||
		Boolean(workspace.pendingOperations?.length);
	useEffect(() => {
		setSelectedTools(missingInstallableTools(kaliVerification?.tools ?? []));
		setSudoPassword("");
	}, [kaliVerification]);
	useEffect(() => {
		if (!kaliDialogOpen) setSudoPassword("");
	}, [kaliDialogOpen]);
	useEffect(() => {
		if (!kaliInstalling) return;
		const beforeUnload = (event: BeforeUnloadEvent) => {
			event.preventDefault();
			event.returnValue = "";
		};
		window.addEventListener("beforeunload", beforeUnload);
		return () => window.removeEventListener("beforeunload", beforeUnload);
	}, [kaliInstalling]);
	async function install() {
		if (connectionBusy || operationBusy || !selectedTools.length) return;
		let result: KaliInstallView | undefined;
		setInstallError("");
		setInstallation(undefined);
		let password = sudoPassword;
		setSudoPassword("");
		try {
			const access = getKaliAccess();
			setInstallTarget(
				`${access.ssh.username}@${access.ssh.host}:${access.ssh.port}`,
			);
			setKaliInstalling(true);
			result = await startKaliInstallation({
				data: { ...access, tools: selectedTools, sudoPassword: password },
			});
			password = "";
			setInstallation(result);
			while (result.state === "running") {
				await new Promise((resolve) => setTimeout(resolve, 1500));
				result = await getKaliInstallation({
					data: { ...access, id: result.id },
				});
				setInstallation(result);
			}
			if (result.state !== "completed")
				throw new Error(result.error || "No se pudo completar la instalación.");
		} catch (error) {
			const message =
				error instanceof Error
					? error.message
					: "No se pudo confirmar la instalación remota. Comprueba Kali antes de reintentar.";
			setInstallError(message);
			if (result?.state === "running")
				setInstallation({
					...result,
					state: "unknown",
					stage: "Resultado sin confirmar",
					error: message,
				});
			recordFailure(workspace.selectedProjectId || null, {
				phase: "analysis",
				stage: "Instalar herramientas en Kali",
				source: "APT",
				target: `${ssh.username}@${ssh.host}`,
				error: message,
			});
		} finally {
			password = "";
			setKaliInstalling(false);
			await verifyKali();
		}
	}
	const fingerprintCheckboxId = useId();
	const update = (patch: Partial<typeof ssh>) =>
		setSsh((current) => ({ ...current, ...patch }));
	return (
		<Dialog
			open={kaliDialogOpen}
			onOpenChange={(open) => {
				if (!kaliInstalling) setKaliDialogOpen(open);
			}}
		>
			<DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-xl">
				<DialogHeader>
					<DialogTitle>Kali por SSH · configuración global</DialogTitle>
					<DialogDescription>
						Elige el entorno donde se ejecutarán las pruebas de todas las fases.
					</DialogDescription>
				</DialogHeader>
				<div className="space-y-4">
					<div className="grid grid-cols-[minmax(0,1fr)_90px] gap-3">
						<PlanField
							label="Host Kali"
							disabled={connectionBusy}
							value={ssh.host}
							placeholder="192.168.1.20"
							onChange={(value) => update({ host: value })}
						/>
						<PlanField
							label="Puerto SSH"
							disabled={connectionBusy}
							type="number"
							min={1}
							max={65535}
							value={ssh.port}
							onChange={(value) => update({ port: Number(value) })}
						/>
					</div>
					<PlanField
						label="Usuario SSH"
						disabled={connectionBusy}
						value={ssh.username}
						placeholder="kali"
						autoComplete="off"
						onChange={(value) => update({ username: value })}
					/>
					<PlanField
						label="Ruta de la clave privada en el servidor de la app"
						disabled={connectionBusy}
						value={ssh.privateKeyPath}
						placeholder="C:\Users\usuario\.ssh\id_ed25519"
						onChange={(value) => update({ privateKeyPath: value })}
					/>
					<PlanField
						label="Frase de contraseña de la clave (opcional)"
						disabled={connectionBusy}
						type="password"
						value={sshPassphrase}
						autoComplete="off"
						onChange={(value) => setSshPassphrase(value)}
					/>
					<p className="text-xs text-muted-foreground">
						Se guardan host, puerto, usuario, ruta y huella en este navegador.
						La frase de contraseña y la verificación solo permanecen en memoria;
						al recargar tendrás que comprobar SSH de nuevo.
					</p>
					<PlanField
						label="Huella del servidor (SHA256)"
						disabled={connectionBusy}
						value={ssh.fingerprint}
						placeholder="SHA256:…"
						onChange={(value) => update({ fingerprint: value })}
					/>
					{observedKaliFingerprint && (
						<Alert>
							<AlertDescription className="space-y-3">
								<p>
									Compara esta huella con la de tu servidor Kali antes de
									aceptarla.
								</p>
								<code className="block break-all text-xs">
									{observedKaliFingerprint}
								</code>
								<label
									htmlFor={fingerprintCheckboxId}
									className="flex items-start gap-2 text-xs"
								>
									<Checkbox
										id={fingerprintCheckboxId}
										checked={trustedFingerprint === observedKaliFingerprint}
										onCheckedChange={(checked) =>
											setTrustedFingerprint(
												checked === true ? observedKaliFingerprint : "",
											)
										}
									/>
									Confirmé la huella por un canal confiable.
								</label>
								<Button
									size="sm"
									variant="outline"
									disabled={trustedFingerprint !== observedKaliFingerprint}
									onClick={() => {
										acceptKaliFingerprint();
										setTrustedFingerprint("");
									}}
								>
									Aceptar huella
								</Button>
							</AlertDescription>
						</Alert>
					)}
					{kaliError && (
						<Alert variant="destructive">
							<AlertDescription className="break-words">
								{kaliError}
							</AlertDescription>
						</Alert>
					)}
					{kaliReady && kaliVerification && (
						<Alert>
							<AlertDescription className="space-y-2">
								<p className="font-medium text-success">
									SSH verificado · Kali listo para las herramientas disponibles
								</p>
								<p>{kaliVerification.version}</p>
								<p>
									Verificación válida hasta{" "}
									{new Date(kaliVerification.expiresAt).toLocaleTimeString()}.
									Cada prueba abrirá su propia sesión SSH. La conexión se
									comprobará automáticamente al recargar y la verificación se
									renovará al caducar.
								</p>
							</AlertDescription>
						</Alert>
					)}
					{kaliReady && kaliVerification?.tools && (
						<KaliToolsStatus tools={kaliVerification.tools} />
					)}
					{kaliReady && missing.length > 0 && (
						<section
							aria-label="Instalación remota"
							className="space-y-3 rounded-lg border p-4"
						>
							<h3 className="text-sm font-medium">
								Instalar herramientas faltantes por SSH
							</h3>
							<p className="text-xs text-muted-foreground">
								Se instalarán en {ssh.host} desde sus repositorios APT, con las
								dependencias necesarias. Elige los paquetes y ejecuta la
								instalación.
							</p>
							{missing.map((tool) => (
								<label
									key={tool}
									htmlFor={`${fingerprintCheckboxId}-install-${tool}`}
									className="flex items-center gap-2 text-sm"
								>
									<Checkbox
										id={`${fingerprintCheckboxId}-install-${tool}`}
										disabled={connectionBusy}
										checked={selectedTools.includes(tool)}
										onCheckedChange={(checked) =>
											setSelectedTools((selected) =>
												checked
													? [...selected.filter((t) => t !== tool), tool]
													: selected.filter((t) => t !== tool),
											)
										}
									/>
									{kaliToolHelp[tool].label} ({installableTools[tool]})
								</label>
							))}
							<PlanField
								label="Contraseña sudo de Kali (opcional)"
								type="password"
								value={sudoPassword}
								onChange={setSudoPassword}
								disabled={connectionBusy}
								autoComplete="off"
								hint="Déjala vacía si eres root o tienes sudo sin contraseña. Se envía solo para esta instalación; no se guarda ni se muestra en los logs."
							/>
							<pre className="overflow-auto rounded bg-muted p-3 text-xs whitespace-pre-wrap">{`apt-get update --error-on=any\napt-get install -y --no-remove --no-install-recommends ${selectedTools.map((t) => installableTools[t]).join(" ")}`}</pre>
							{operationBusy && !kaliInstalling && (
								<p className="text-xs text-warning">
									Espera a que terminen las pruebas en curso antes de instalar.
								</p>
							)}
							<Button
								disabled={
									connectionBusy || operationBusy || !selectedTools.length
								}
								onClick={() => void install()}
							>
								{kaliInstalling
									? "Instalando en Kali…"
									: "Instalar herramientas seleccionadas"}
							</Button>
							<p className="text-xs text-muted-foreground">
								cve-search requiere configurar su servicio y su base por
								separado. NVD no requiere instalación.
							</p>
						</section>
					)}
					{installError && (
						<Alert variant="destructive">
							<AlertDescription>{installError}</AlertDescription>
						</Alert>
					)}
					{(kaliInstalling || installation) && (
						<section
							className="space-y-3 rounded-lg border p-3"
							aria-label="Progreso de instalación"
						>
							<output className="block text-sm" aria-live="polite">
								{installation?.stage || "Iniciando instalación…"} ·{" "}
								{installTarget}
							</output>
							{installation?.state === "completed" && (
								<p className="text-xs text-success">
									APT terminó. La disponibilidad de las herramientas se vuelve a
									comprobar automáticamente.
								</p>
							)}
							{installation?.logs && (
								<pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">
									{installation.logs}
								</pre>
							)}
							{installation?.truncated && (
								<p className="text-xs text-warning">
									Registro recortado a los últimos 100.000 caracteres.
								</p>
							)}
							{kaliInstalling && (
								<p className="text-xs text-muted-foreground">
									Mantén esta página abierta mientras se instala. Si se pierde
									SSH, el resultado se mostrará sin confirmar.
								</p>
							)}
						</section>
					)}
					<Button
						disabled={
							connectionBusy ||
							!ssh.host ||
							!ssh.username ||
							!ssh.privateKeyPath
						}
						onClick={() => void verifyKali()}
					>
						{kaliChecking && <LoaderCircle className="size-4 animate-spin" />}
						{kaliChecking
							? "Comprobando Kali…"
							: "Comprobar SSH y herramientas"}
					</Button>
				</div>
			</DialogContent>
		</Dialog>
	);
}
