import { LoaderCircle, Server, ShieldCheck } from "lucide-react";
import { useId, useState } from "react";
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

export function KaliConnectionButton() {
	const {
		kaliReady,
		kaliChecking,
		kaliError,
		kaliVerification,
		setKaliDialogOpen,
	} = useWorkspace();
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
				<ShieldCheck className="size-4 text-success" />
			) : (
				<Server className="size-4" />
			)}
			<span>
				{kaliChecking
					? "Comprobando Kali…"
					: kaliReady
						? "Kali verificado"
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
	} = useWorkspace();
	const [trustedFingerprint, setTrustedFingerprint] = useState("");
	const fingerprintCheckboxId = useId();
	const update = (patch: Partial<typeof ssh>) =>
		setSsh((current) => ({ ...current, ...patch }));
	return (
		<Dialog open={kaliDialogOpen} onOpenChange={setKaliDialogOpen}>
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
							disabled={kaliChecking}
							value={ssh.host}
							placeholder="192.168.1.20"
							onChange={(value) => update({ host: value })}
						/>
						<PlanField
							label="Puerto SSH"
							disabled={kaliChecking}
							type="number"
							min={1}
							max={65535}
							value={ssh.port}
							onChange={(value) => update({ port: Number(value) })}
						/>
					</div>
					<PlanField
						label="Usuario SSH"
						disabled={kaliChecking}
						value={ssh.username}
						placeholder="kali"
						autoComplete="off"
						onChange={(value) => update({ username: value })}
					/>
					<PlanField
						label="Ruta de la clave privada en el servidor de la app"
						disabled={kaliChecking}
						value={ssh.privateKeyPath}
						placeholder="C:\Users\usuario\.ssh\id_ed25519"
						onChange={(value) => update({ privateKeyPath: value })}
					/>
					<PlanField
						label="Frase de contraseña de la clave (opcional)"
						disabled={kaliChecking}
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
						disabled={kaliChecking}
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
									Kali verificado para todas las fases
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
					<Button
						disabled={
							kaliChecking || !ssh.host || !ssh.username || !ssh.privateKeyPath
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
