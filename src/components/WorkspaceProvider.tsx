import { Link } from "@tanstack/react-router";
import { LoaderCircle } from "lucide-react";
import {
	createContext,
	type Dispatch,
	type ReactNode,
	type SetStateAction,
	useCallback,
	useContext,
	useEffect,
	useMemo,
	useRef,
	useState,
} from "react";
import {
	type ExecutionSnapshot,
	type ExecutionView,
	isActiveJob,
} from "../lib/execution.ts";
import { saveExecutionResult } from "../lib/execution-history.ts";
import {
	kaliReady as isKaliReady,
	type KaliAccess,
	KaliAutoVerification,
	type KaliVerification,
	sshSettingsSignature,
} from "../lib/kali.ts";
import { parseNmapCommand, quoteArg } from "../lib/nmap-command.ts";
import {
	appendFailure,
	type FailureInput,
	makeFailure,
	recoverPendingOperations,
} from "../lib/operation-history.ts";
import {
	defaultSshSettings,
	emptyWorkspace,
	readActiveExecution,
	readSshSettings,
	readWorkspaceResult,
	type SavedSshSettings,
	type WorkspaceData,
	writeActiveExecution,
	writeSshSettings,
	writeWorkspace,
} from "../lib/storage.ts";
import {
	cancelNmapJob,
	getNmapArtifact,
	getNmapJob,
	type StartJobInput,
	startNmapJob,
	verifySsh,
} from "../server/jobs";
import { KaliConnectionDialog } from "./KaliConnection";
import { NewProjectDialog } from "./ProjectCreation";
import { Button } from "./ui/button";

type WorkspaceContextValue = {
	workspace: WorkspaceData;
	recordFailure: (projectId: string | null, input: FailureInput) => void;
	beginOperation: (projectId: string, input: FailureInput) => string;
	finishOperation: (id: string) => void;
	setWorkspace: Dispatch<SetStateAction<WorkspaceData>>;
	replaceWorkspace: (data: WorkspaceData) => void;
	hydrated: boolean;
	projectDialogOpen: boolean;
	setProjectDialogOpen: (open: boolean) => void;
	projectCreationBlocked: boolean;
	setProjectCreationBlocked: (blocked: boolean) => void;
	storageError: string;
	setStorageError: (value: string) => void;
	ssh: SavedSshSettings;
	setSsh: Dispatch<SetStateAction<SavedSshSettings>>;
	sshPassphrase: string;
	setSshPassphrase: (value: string) => void;
	kaliVerification: KaliVerification | null;
	kaliReady: boolean;
	kaliChecking: boolean;
	kaliInstalling: boolean;
	setKaliInstalling: (value: boolean) => void;
	kaliError: string;
	observedKaliFingerprint: string;
	kaliDialogOpen: boolean;
	setKaliDialogOpen: (value: boolean) => void;
	verifyKali: () => Promise<void>;
	acceptKaliFingerprint: () => void;
	getKaliAccess: () => KaliAccess;
	execution: ExecutionView | null;
	startingRequest: boolean;
	startExecution: (input: StartJobInput) => Promise<void>;
	cancelExecution: () => Promise<void>;
};
const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);
export function useWorkspace() {
	const context = useContext(WorkspaceContext);
	if (!context) throw new Error("WorkspaceProvider no está disponible.");
	return context;
}
export function WorkspaceProvider({ children }: { children: ReactNode }) {
	const [workspace, setWorkspace] = useState<WorkspaceData>(emptyWorkspace);
	const recordFailure = useCallback(
		(projectId: string | null, input: FailureInput) => {
			const failure = makeFailure(input);
			setWorkspace((current) => appendFailure(current, projectId, failure));
		},
		[],
	);
	const beginOperation = useCallback(
		(projectId: string, input: FailureInput) => {
			const pending = { ...makeFailure(input), projectId };
			setWorkspace((current) => ({
				...current,
				pendingOperations: [...(current.pendingOperations ?? []), pending],
			}));
			return pending.id;
		},
		[],
	);
	const finishOperation = useCallback((id: string) => {
		setWorkspace((current) => ({
			...current,
			pendingOperations: (current.pendingOperations ?? []).filter(
				(p) => p.id !== id,
			),
		}));
	}, []);
	const [projectDialogOpen, setProjectDialogOpen] = useState(false);
	const [projectCreationBlocked, setProjectCreationBlocked] = useState(false);
	const [ssh, updateSsh] = useState<SavedSshSettings>(defaultSshSettings);
	const [sshPassphrase, updatePassphrase] = useState("");
	const [kaliVerification, setKaliVerification] =
		useState<KaliVerification | null>(null);
	const [kaliChecking, setKaliChecking] = useState(false);
	const [kaliInstalling, updateKaliInstalling] = useState(false);
	const installingKali = useRef(false);
	const setKaliInstalling = useCallback((value: boolean) => {
		installingKali.current = value;
		updateKaliInstalling(value);
	}, []);
	const checkingKali = useRef(false);
	const autoKaliVerification = useRef(new KaliAutoVerification());
	const [kaliError, setKaliError] = useState("");
	const [observedKaliFingerprint, setObservedKaliFingerprint] = useState("");
	const [kaliDialogOpen, setKaliDialogOpen] = useState(false);
	const [kaliClock, setKaliClock] = useState(Date.now());
	const settings = useMemo(
		() => ({ ...ssh, passphrase: sshPassphrase || undefined }),
		[ssh, sshPassphrase],
	);
	const settingsRef = useRef(settings);
	settingsRef.current = settings;
	const kaliReady = isKaliReady(kaliVerification, settings, kaliClock);
	useEffect(() => {
		const timer = setInterval(() => setKaliClock(Date.now()), 5000);
		return () => clearInterval(timer);
	}, []);
	const setSsh: Dispatch<SetStateAction<SavedSshSettings>> = (value) => {
		setKaliVerification(null);
		setKaliError("");
		setObservedKaliFingerprint("");
		updateSsh((current) => {
			const next = typeof value === "function" ? value(current) : value;
			return next.host !== current.host || next.port !== current.port
				? { ...next, fingerprint: "" }
				: next;
		});
	};
	const setSshPassphrase = (value: string) => {
		setKaliVerification(null);
		setKaliError("");
		updatePassphrase(value);
	};
	const acceptKaliFingerprint = () => {
		if (!observedKaliFingerprint) return;
		updateSsh((current) => ({
			...current,
			fingerprint: observedKaliFingerprint,
		}));
		setKaliVerification(null);
		setObservedKaliFingerprint("");
		setKaliError("");
	};
	const verifyKali = useCallback(async () => {
		if (checkingKali.current || installingKali.current) return;
		checkingKali.current = true;
		setKaliChecking(true);
		setKaliVerification(null);
		setKaliError("");
		setObservedKaliFingerprint("");
		const captured = { ...settingsRef.current };
		const signature = sshSettingsSignature(captured);
		const failureContext = {
			phase: (window.location.pathname.startsWith("/reconocimiento")
				? "recon"
				: window.location.pathname.startsWith("/analisis")
					? "analysis"
					: "enumeration") as "recon" | "enumeration" | "analysis",
			stage: "Verificar SSH y herramientas",
			target: `${captured.username}@${captured.host}:${captured.port}`,
		};
		const projectId = workspace.selectedProjectId;
		try {
			const result = await verifySsh({ data: captured });
			if (sshSettingsSignature(settingsRef.current) !== signature) return;
			if (result.connected) {
				setKaliVerification({
					token: result.token,
					expiresAt: result.expiresAt,
					version: result.version,
					executor: result.executor,
					settingsSignature: signature,
					tools: result.tools,
				});
				setKaliClock(Date.now());
			} else {
				setKaliError(result.error ?? "No se pudo verificar Kali.");
				recordFailure(projectId, {
					...failureContext,
					error: result.error || "No se pudo verificar Kali.",
				});
				if (result.fingerprint && result.fingerprint !== captured.fingerprint)
					setObservedKaliFingerprint(result.fingerprint);
			}
		} catch (error) {
			recordFailure(projectId, {
				...failureContext,
				error:
					error instanceof Error ? error.message : "No se pudo verificar Kali.",
			});
			if (sshSettingsSignature(settingsRef.current) === signature)
				setKaliError(
					error instanceof Error ? error.message : "No se pudo verificar Kali.",
				);
		} finally {
			checkingKali.current = false;
			setKaliChecking(false);
		}
	}, [recordFailure, workspace.selectedProjectId]);
	const getKaliAccess = (): KaliAccess => {
		if (installingKali.current)
			throw new Error(
				"Espera a que termine la instalación de herramientas en Kali.",
			);
		if (
			!kaliVerification ||
			!isKaliReady(kaliVerification, settingsRef.current)
		) {
			setKaliDialogOpen(true);
			throw new Error("Comprueba la conexión global a Kali antes de ejecutar.");
		}
		return {
			mode: "ssh",
			ssh: { ...settingsRef.current },
			kaliToken: kaliVerification.token,
		};
	};
	const [hydrated, setHydrated] = useState(false);
	const [storageError, setStorageError] = useState("");
	const [execution, setExecution] = useState<ExecutionView | null>(null);
	const [startingRequest, setStartingRequest] = useState(false);
	const allowPersistence = useRef(true);
	const storageFailureRef = useRef("");
	const snapshotRef = useRef<ExecutionSnapshot | null>(null);
	const startingRef = useRef(false);
	const finalizingRef = useRef(false);
	const executionId = execution?.id;
	const executionState = execution?.state;
	const executionProjectId = execution?.projectId;
	useEffect(() => {
		const stored = readWorkspaceResult();
		setWorkspace(recoverPendingOperations(stored.data));
		allowPersistence.current = !stored.error;
		if (stored.error) setStorageError(stored.error);
		updateSsh(readSshSettings());
		const active = readActiveExecution();
		if (active) {
			snapshotRef.current = active;
			setExecution({
				...active,
				state: "starting",
				logs: "",
				truncated: false,
				artifactAvailable: false,
			});
		}
		setHydrated(true);
	}, []);
	useEffect(() => {
		if (!hydrated || kaliChecking || checkingKali.current || kaliInstalling)
			return;
		if (
			autoKaliVerification.current.claim(
				settings,
				kaliVerification,
				checkingKali.current,
				kaliClock,
			)
		)
			void verifyKali();
	}, [
		hydrated,
		settings,
		kaliVerification,
		kaliChecking,
		kaliInstalling,
		kaliClock,
		verifyKali,
	]);
	useEffect(() => {
		if (!hydrated || !allowPersistence.current) return;
		const result = writeWorkspace(workspace);
		if (!result.ok) {
			setStorageError(result.message);
			if (storageFailureRef.current !== result.message) {
				storageFailureRef.current = result.message;
				recordFailure(workspace.selectedProjectId, {
					phase: window.location.pathname.startsWith("/reconocimiento")
						? "recon"
						: window.location.pathname.startsWith("/analisis")
							? "analysis"
							: "enumeration",
					stage: "Guardar datos en el navegador",
					error: `${result.message} El registro está en memoria; descarga una copia antes de cerrar.`,
				});
			}
		} else {
			storageFailureRef.current = "";
			setStorageError("");
			if (
				executionId &&
				executionState &&
				!isActiveJob(executionState) &&
				workspace.projects
					.find((project) => project.id === executionProjectId)
					?.lastRuns?.some((run) => run.id === executionId)
			) {
				if (!writeActiveExecution(null))
					setStorageError(
						"No pude limpiar la referencia de la ejecución en este navegador.",
					);
			}
		}
	}, [
		workspace,
		hydrated,
		executionId,
		executionState,
		executionProjectId,
		recordFailure,
	]);
	useEffect(() => {
		if (hydrated && !writeSshSettings(ssh))
			setStorageError("No pude guardar la configuración SSH.");
	}, [ssh, hydrated]);
	useEffect(() => {
		const snapshot = snapshotRef.current;
		if (!hydrated || !snapshot || execution?.id !== snapshot.id) return;
		let disposed = false;
		let fetching = false;
		let completed = false;
		let offset = 0;
		let logs = "";
		const poll = async () => {
			if (disposed || fetching || completed) return;
			fetching = true;
			try {
				const result = await getNmapJob({ data: { id: snapshot.id, offset } });
				if (disposed) return;
				if (!result.found) {
					completed = true;
					const error =
						"El servidor ya no conoce esta ejecución. Su terminación no está confirmada; revisa el proceso en el ejecutor.";
					setExecution({
						...snapshot,
						state: "unknown",
						logs,
						truncated: false,
						artifactAvailable: false,
						error,
					});
					setWorkspace((current) =>
						saveExecutionResult(current, snapshot, {
							state: "unknown",
							logs,
							date: new Date().toISOString(),
							truncated: false,
							error,
						}),
					);
					return;
				}
				offset = result.offset;
				logs = result.gap ? result.logs : (logs + result.logs).slice(-1500000);
				setExecution({
					...snapshot,
					state: result.state,
					logs,
					error: result.error,
					truncated: result.truncated,
					artifactAvailable: result.artifactAvailable,
					finishedAt: result.finishedAt,
				});
				if (!isActiveJob(result.state)) {
					finalizingRef.current = true;
					completed = true;
					let xml: string | undefined;
					if (result.artifactAvailable) {
						try {
							const artifact = await getNmapArtifact({
								data: { id: snapshot.id },
							});
							if (!artifact)
								throw new Error("El XML anunciado ya no está disponible.");
							xml = artifact.text;
						} catch (error) {
							recordFailure(snapshot.projectId, {
								phase: "enumeration",
								stage: "Recuperar XML",
								jobId: snapshot.id,
								scopeRevision: snapshot.scopeRevision,
								error:
									error instanceof Error
										? error.message
										: "No se pudo recuperar el XML.",
							});
						}
					}
					if (!disposed)
						setWorkspace((current) =>
							saveExecutionResult(current, snapshot, {
								state: result.state,
								logs,
								xml,
								date: result.finishedAt ?? new Date().toISOString(),
								truncated: result.truncated,
								error: result.error,
							}),
						);
				}
			} catch (error) {
				if (!disposed)
					recordFailure(snapshot.projectId, {
						id: `${snapshot.id}:poll`,
						phase: "enumeration",
						stage: "Consultar ejecución",
						jobId: snapshot.id,
						error: error instanceof Error ? error.message : "Consulta fallida.",
					});
				if (!disposed)
					setExecution((current) =>
						current?.id === snapshot.id
							? {
									...current,
									error: `No pude consultar el trabajo; reintentando. ${error instanceof Error ? error.message : ""}`,
								}
							: current,
					);
			} finally {
				finalizingRef.current = false;
				fetching = false;
			}
		};
		void poll();
		const timer = window.setInterval(() => void poll(), 800);
		return () => {
			disposed = true;
			window.clearInterval(timer);
		};
	}, [execution?.id, hydrated, recordFailure]);
	const replaceWorkspace = useCallback(
		(data: WorkspaceData) => {
			if (finalizingRef.current)
				throw new Error(
					"Espera a que se guarde el resultado antes de importar proyectos.",
				);
			if (
				execution &&
				isActiveJob(execution.state) &&
				!data.projects.some((project) => project.id === execution.projectId)
			)
				throw new Error(
					"La importación quitaría el proyecto de una ejecución activa. Espera a que termine.",
				);
			allowPersistence.current = true;
			setWorkspace(recoverPendingOperations(data));
		},
		[execution],
	);
	const startExecution = useCallback(
		async (input: StartJobInput) => {
			if (finalizingRef.current)
				throw new Error(
					"Se está guardando el resultado anterior. Espera un momento.",
				);
			if (startingRef.current || (execution && isActiveJob(execution.state)))
				throw new Error("Ya hay una ejecución activa en este navegador.");
			const parsed = parseNmapCommand(
				["nmap", ...input.args].map(quoteArg).join(" "),
			);
			const immutableInput = {
				...input,
				args: [...input.args],
				ssh: { ...input.ssh },
				plan: input.plan ? structuredClone(input.plan) : undefined,
			};
			startingRef.current = true;
			setStartingRequest(true);
			try {
				const result = await startNmapJob({ data: immutableInput });
				const snapshot: ExecutionSnapshot = {
					id: result.id,
					projectId: input.projectId,
					command: result.command,
					targets: parsed.targets,
					mode: input.mode,
					startedAt: result.startedAt,
					scopeRevision: result.scopeRevision,
					executor: result.executor,
				};
				snapshotRef.current = snapshot;
				if (!writeActiveExecution(snapshot))
					setStorageError(
						"El trabajo inició, pero el navegador no pudo guardar su referencia para recuperarlo tras una recarga.",
					);
				setExecution({
					...snapshot,
					state: "starting",
					logs: "",
					truncated: false,
					artifactAvailable: false,
				});
			} finally {
				startingRef.current = false;
				setStartingRequest(false);
			}
		},
		[execution],
	);
	const cancelExecution = useCallback(async () => {
		if (!execution || !isActiveJob(execution.state)) return;
		try {
			const result = await cancelNmapJob({ data: { id: execution.id } });
			setExecution((current) =>
				current?.id === execution.id &&
				isActiveJob(current.state) &&
				result.requested
					? { ...current, state: "cancelling" }
					: current,
			);
		} catch (error) {
			recordFailure(execution.projectId, {
				phase: "enumeration",
				stage: "Solicitar cancelación",
				jobId: execution.id,
				error:
					error instanceof Error ? error.message : "Cancelación no confirmada.",
			});
			setExecution((current) =>
				current
					? {
							...current,
							error: `No se confirmó la solicitud de cancelación: ${error instanceof Error ? error.message : ""}`,
						}
					: current,
			);
		}
	}, [execution, recordFailure]);
	return (
		<WorkspaceContext.Provider
			value={{
				workspace,
				recordFailure,
				beginOperation,
				finishOperation,
				setWorkspace,
				replaceWorkspace,
				hydrated,
				projectDialogOpen,
				setProjectDialogOpen,
				projectCreationBlocked: projectCreationBlocked || kaliInstalling,
				setProjectCreationBlocked,
				storageError,
				setStorageError,
				ssh,
				setSsh,
				sshPassphrase,
				setSshPassphrase,
				kaliVerification,
				kaliReady,
				kaliChecking,
				kaliInstalling,
				setKaliInstalling,
				kaliError,
				observedKaliFingerprint,
				kaliDialogOpen,
				setKaliDialogOpen,
				verifyKali,
				acceptKaliFingerprint,
				getKaliAccess,
				execution,
				startingRequest,
				startExecution,
				cancelExecution,
			}}
		>
			{children}
			<KaliConnectionDialog />
			<NewProjectDialog />
			{execution && isActiveJob(execution.state) && (
				<div className="fixed bottom-3 right-3 z-40 flex max-w-[calc(100vw-1.5rem)] items-center gap-3 rounded-xl border bg-card px-4 py-3 shadow-xl">
					<LoaderCircle className="size-4 shrink-0 animate-spin text-primary" />
					<Link to="/enumeracion" className="min-w-0 text-xs hover:underline">
						<span className="block truncate font-medium">
							Nmap ·{" "}
							{workspace.projects.find(
								(project) => project.id === execution.projectId,
							)?.name ?? "Proyecto"}
						</span>
						<span className="text-muted-foreground">
							{execution.state === "cancelling"
								? "Confirmando terminación…"
								: "Ver ejecución activa"}
						</span>
					</Link>
					<Button
						size="sm"
						variant="outline"
						disabled={execution.state === "cancelling"}
						onClick={() => void cancelExecution()}
					>
						Cancelar
					</Button>
				</div>
			)}
		</WorkspaceContext.Provider>
	);
}
