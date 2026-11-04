import "@xterm/xterm/css/xterm.css";
import type { Terminal } from "@xterm/xterm";
import {
	Check,
	Copy,
	Eraser,
	LoaderCircle,
	TerminalSquare,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { KaliAccess } from "#/lib/kali";
import type { TerminalSession } from "#/lib/terminal";
import { terminalOutput } from "#/lib/terminal-output";
import {
	closeTerminal,
	readTerminal,
	resizeTerminal,
	startTerminal,
	writeTerminal,
} from "#/server/terminal";
import { Alert, AlertDescription } from "./ui/alert";
import { Button } from "./ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "./ui/dialog";
import { useWorkspace } from "./WorkspaceProvider";

function TerminalPanel({ access }: { access: KaliAccess }) {
	const container = useRef<HTMLDivElement>(null);
	const emulator = useRef<Terminal | null>(null);
	const [status, setStatus] = useState("Conectando con Kali…");
	const [connected, setConnected] = useState(false);
	const [error, setError] = useState("");
	const [copying, setCopying] = useState(false);
	const [copied, setCopied] = useState(false);
	const [copyError, setCopyError] = useState("");

	useEffect(() => {
		if (!copied) return;
		const timer = setTimeout(() => setCopied(false), 2000);
		return () => clearTimeout(timer);
	}, [copied]);

	const copyOutput = async () => {
		setCopyError("");
		setCopied(false);
		setCopying(true);
		try {
			if (!emulator.current) throw new Error("Terminal no disponible");
			await navigator.clipboard.writeText(
				terminalOutput(emulator.current.buffer.active),
			);
			setCopied(true);
		} catch {
			setCopyError(
				"No se pudo copiar la salida. Comprueba los permisos del portapapeles.",
			);
		} finally {
			setCopying(false);
		}
	};

	useEffect(() => {
		let disposed = false;
		let stopped = false;
		let session: TerminalSession | undefined;
		let terminal: Terminal | undefined;
		let observer: ResizeObserver | undefined;
		let pollTimer: ReturnType<typeof setTimeout> | undefined;
		let inputTimer: ReturnType<typeof setTimeout> | undefined;
		let resizeTimer: ReturnType<typeof setTimeout> | undefined;
		let pendingInput = "";
		let sending = false;

		const disconnect = () => {
			if (session) {
				const closing = session;
				session = undefined;
				void closeTerminal({
					data: closing,
					signal: AbortSignal.timeout(5000),
				}).catch(() => {
					// The server also expires sessions if the browser disappears.
				});
			}
		};
		const stop = (message: string, failed = false) => {
			if (disposed || stopped) return;
			stopped = true;
			clearTimeout(pollTimer);
			clearTimeout(inputTimer);
			clearTimeout(resizeTimer);
			pendingInput = "";
			if (terminal) terminal.options.disableStdin = true;
			setConnected(false);
			setStatus(message);
			if (failed) setError(message);
			disconnect();
		};
		const fail = (cause: unknown) =>
			stop(
				cause instanceof Error
					? cause.message
					: "No se pudo mantener la conexión con la terminal.",
				true,
			);
		const sendInput = async () => {
			if (sending || !session || stopped || disposed) return;
			sending = true;
			try {
				while (pendingInput && session && !stopped && !disposed) {
					let length = Math.min(4096, pendingInput.length);
					const last = pendingInput.charCodeAt(length - 1);
					if (length < pendingInput.length && last >= 0xd800 && last <= 0xdbff)
						length--;
					const input = pendingInput.slice(0, length);
					pendingInput = pendingInput.slice(length);
					// Sequential, never retried: a timeout must not execute input twice.
					await writeTerminal({
						data: { ...session, input },
						signal: AbortSignal.timeout(10000),
					});
				}
			} catch (cause) {
				fail(cause);
			} finally {
				sending = false;
			}
		};

		async function initialize() {
			const [{ Terminal: Xterm }, { FitAddon }] = await Promise.all([
				import("@xterm/xterm"),
				import("@xterm/addon-fit"),
			]);
			if (disposed || !container.current) return;
			terminal = new Xterm({
				cursorBlink: true,
				disableStdin: true,
				fontFamily: "Consolas, 'Liberation Mono', monospace",
				fontSize: 14,
				scrollback: 3000,
				screenReaderMode: true,
				theme: { background: "#09090b", foreground: "#f4f4f5" },
			});
			const fit = new FitAddon();
			terminal.loadAddon(fit);
			terminal.open(container.current);
			emulator.current = terminal;
			const fitSize = () => {
				const proposed = fit.proposeDimensions();
				if (proposed && terminal)
					terminal.resize(
						Math.max(2, Math.min(500, proposed.cols)),
						Math.max(1, Math.min(200, proposed.rows)),
					);
			};
			fitSize();
			terminal.textarea?.setAttribute("aria-label", "Entrada de terminal SSH");
			terminal.onData((input) => {
				if (!session || stopped || disposed) return;
				if (pendingInput.length + input.length > 128 * 1024) {
					fail(
						new Error(
							"La entrada es demasiado extensa. Divide el texto pegado.",
						),
					);
					return;
				}
				pendingInput += input;
				clearTimeout(inputTimer);
				inputTimer = setTimeout(() => void sendInput(), 10);
			});
			const created = await startTerminal({
				data: { ...access, cols: terminal.cols, rows: terminal.rows },
			});
			session = created;
			if (disposed) {
				disconnect();
				return;
			}
			terminal.options.disableStdin = false;
			terminal.focus();
			setConnected(true);
			setStatus("Conectada por SSH");
			observer = new ResizeObserver(() => {
				clearTimeout(resizeTimer);
				resizeTimer = setTimeout(() => {
					if (!session || stopped || disposed || !terminal) return;
					fitSize();
					void resizeTerminal({
						data: { ...session, cols: terminal.cols, rows: terminal.rows },
						signal: AbortSignal.timeout(10000),
					}).catch(fail);
				}, 120);
			});
			observer.observe(container.current);
			let offset = 0;
			const poll = async () => {
				if (!session || stopped || disposed || !terminal) return;
				try {
					const frame = await readTerminal({
						data: { ...session, offset },
						signal: AbortSignal.timeout(10000),
					});
					if (disposed || stopped) return;
					if (frame.truncated) {
						terminal.reset();
						terminal.write(
							"\r\n[Salida anterior omitida por el límite de memoria]\r\n",
						);
					}
					if (frame.data)
						await new Promise<void>((resolve) =>
							terminal?.write(frame.data, resolve),
						);
					if (disposed || stopped) return;
					offset = frame.offset;
					if (frame.state === "closed") {
						stop(frame.message);
						return;
					}
					pollTimer = setTimeout(() => void poll(), frame.data ? 40 : 160);
				} catch (cause) {
					fail(cause);
				}
			};
			void poll();
		}
		void initialize().catch(fail);
		const beforeUnload = (event: BeforeUnloadEvent) => {
			if (!session || stopped) return;
			event.preventDefault();
			event.returnValue = "";
		};
		const pageHide = () => disconnect();
		window.addEventListener("beforeunload", beforeUnload);
		window.addEventListener("pagehide", pageHide);
		return () => {
			disposed = true;
			clearTimeout(pollTimer);
			clearTimeout(inputTimer);
			clearTimeout(resizeTimer);
			observer?.disconnect();
			window.removeEventListener("beforeunload", beforeUnload);
			window.removeEventListener("pagehide", pageHide);
			disconnect();
			terminal?.dispose();
			emulator.current = null;
		};
	}, [access]);

	return (
		<div className="min-w-0 space-y-3">
			<div className="flex flex-wrap items-center gap-2">
				<output className="mr-auto text-xs" aria-live="polite">
					{status}
				</output>
				<Button
					variant="outline"
					size="sm"
					disabled={!connected}
					onClick={() => {
						emulator.current?.input("\x03", true);
						emulator.current?.focus();
					}}
				>
					Ctrl+C
				</Button>
				<Button
					variant="outline"
					size="sm"
					onClick={() => {
						emulator.current?.clear();
						emulator.current?.focus();
					}}
				>
					<Eraser className="size-4" /> Limpiar vista
				</Button>
				<Button
					variant="outline"
					size="sm"
					disabled={copying}
					onClick={() => void copyOutput()}
					title="Copiar toda la salida conservada, incluido el historial"
				>
					{copied ? <Check className="size-4" /> : <Copy className="size-4" />}
					<span aria-live="polite">{copied ? "Copiado" : "Copiar todo"}</span>
				</Button>
			</div>
			{copyError && (
				<p role="alert" className="text-xs text-destructive">
					{copyError}
				</p>
			)}
			{error && (
				<Alert variant="destructive">
					<AlertDescription>
						{error} Cierra y vuelve a abrir la terminal para iniciar otra
						sesión.
					</AlertDescription>
				</Alert>
			)}
			<div
				ref={container}
				className="h-[min(55dvh,560px)] min-h-40 min-w-0 overflow-hidden rounded-md border bg-[#09090b] p-2 text-left"
			/>
			<p className="text-xs text-muted-foreground">
				Shell manual con los permisos de {access.ssh.username}. Los comandos no
				se validan contra el plan ni se guardan en los informes. Al cerrar se
				cierra esta sesión SSH; los procesos desacoplados pueden continuar en
				Kali.
			</p>
		</div>
	);
}

export function KaliTerminalButton() {
	const {
		kaliReady,
		kaliChecking,
		kaliInstalling,
		getKaliAccess,
		setKaliDialogOpen,
	} = useWorkspace();
	const [access, setAccess] = useState<KaliAccess>();
	const trigger = useRef<HTMLButtonElement>(null);
	return (
		<Dialog
			open={!!access}
			onOpenChange={(open) => !open && setAccess(undefined)}
		>
			<Button
				ref={trigger}
				variant="outline"
				size="sm"
				aria-label="Abrir terminal SSH de Kali"
				disabled={kaliChecking || kaliInstalling}
				title={
					kaliReady
						? "Abrir terminal en Kali"
						: "Configura y verifica Kali para abrir la terminal"
				}
				onClick={() => {
					try {
						setAccess(getKaliAccess());
					} catch {
						setKaliDialogOpen(true);
					}
				}}
			>
				{kaliChecking ? (
					<LoaderCircle className="size-4 animate-spin" />
				) : (
					<TerminalSquare className="size-4" />
				)}
				<span className="hidden sm:inline">Terminal</span>
			</Button>
			<DialogContent
				className="max-h-[95dvh] overflow-y-auto sm:max-w-5xl"
				onOpenAutoFocus={(event) => event.preventDefault()}
				onCloseAutoFocus={(event) => {
					event.preventDefault();
					trigger.current?.focus();
				}}
				onEscapeKeyDown={(event) => event.preventDefault()}
				onInteractOutside={(event) => event.preventDefault()}
			>
				<DialogHeader className="min-w-0 pr-6">
					<DialogTitle>Terminal remota · Kali</DialogTitle>
					<DialogDescription className="break-all">
						{access &&
							`${access.ssh.username}@${access.ssh.host}:${access.ssh.port}`}
						{" · Misma configuración SSH del sistema. Usa × para cerrar."}
					</DialogDescription>
				</DialogHeader>
				{access && <TerminalPanel access={access} />}
				<Button variant="outline" onClick={() => setAccess(undefined)}>
					Cerrar terminal y desconectar
				</Button>
			</DialogContent>
		</Dialog>
	);
}
