import { LoaderCircle, Play, Save } from "lucide-react";
import { useState } from "react";
import {
	buildReconCommand,
	defaultReconQuery,
	parseCrtResult,
	parseRdapResult,
	parseReconCommand,
	publicDomain,
	type ReconQuery,
	type ReconResult,
	reconQueryIssues,
	reconQueryUrl,
	reconTarget,
	scopeManualResult,
} from "#/lib/recon";
import { addressRange } from "#/lib/scope";
import type { WorkspaceProject } from "#/lib/storage";
import { KaliConnectionButton } from "../KaliConnection";
import {
	isoDateInput,
	localDateInput,
	PlanField,
} from "../planning/PlanFields";
import { Alert, AlertDescription } from "../ui/alert";
import { Button } from "../ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "../ui/card";
import { Checkbox } from "../ui/checkbox";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "../ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { useWorkspace } from "../WorkspaceProvider";

export function ReconCollector({
	project,
	busy,
	onQuery,
	onSave,
	failedQuery,
}: {
	project: WorkspaceProject;
	busy: boolean;
	onQuery: (query: ReconQuery) => Promise<void>;
	onSave: (result: ReconResult, notes: string) => void;
	failedQuery?: ReconQuery;
}) {
	const { kaliReady, recordFailure } = useWorkspace();
	const [query, setQuery] = useState<ReconQuery>(() => ({
		...defaultReconQuery(),
		domain:
			project.plan?.includes.find((value) => {
				try {
					reconTarget(value);
					return true;
				} catch {
					return false;
				}
			}) ?? "",
	}));
	const [command, setCommand] = useState(() => {
		try {
			return buildReconCommand(query);
		} catch {
			return "";
		}
	});
	const [commandError, setCommandError] = useState("");
	const [manualError, setManualError] = useState("");
	const [kind, setKind] = useState("manual");
	const [queryLabel, setQueryLabel] = useState("");
	const [sourceUrl, setSourceUrl] = useState("");
	const [content, setContent] = useState("");
	const [notes, setNotes] = useState("");
	const [observedAt, setObservedAt] = useState(() => new Date().toISOString());
	const [tab, setTab] = useState("public");
	const externalSource = query.source === "crtsh" || query.source === "rdap";
	const ipTarget =
		!query.domain.includes("/") && !!addressRange(query.domain.trim());
	const issues = reconQueryIssues(query, project.plan);
	const updateQuery = (patch: Partial<ReconQuery>) => {
		const next = { ...query, ...patch };
		if (
			addressRange(next.domain.trim()) &&
			(next.source === "crtsh" || next.source === "rdap")
		) {
			next.source = "dns";
			next.subdomains = false;
		}
		setQuery(next);
		setCommandError("");
		try {
			setCommand(buildReconCommand(next));
		} catch {
			setCommand("");
		}
	};
	function saveManual() {
		try {
			let result: ReconResult;
			if (kind === "manual")
				result = scopeManualResult(
					content,
					queryLabel,
					sourceUrl,
					observedAt,
					project.plan?.status === "approved"
						? project.plan.revision
						: undefined,
				);
			else {
				if (content.length > 3 * 1024 * 1024)
					throw new Error("La evidencia supera 3 MB.");
				const importedQuery = {
					...defaultReconQuery(),
					domain: publicDomain(queryLabel),
					source: kind as "crtsh" | "rdap",
					subdomains: kind === "crtsh",
				};
				const parsed =
					kind === "crtsh"
						? parseCrtResult(JSON.parse(content), importedQuery)
						: parseRdapResult(JSON.parse(content), importedQuery.domain);
				result = {
					...parsed,
					warnings: [
						"JSON aportado por el operador: la fecha y la procedencia declaradas no se verificaron mediante una consulta en la app.",
						...parsed.warnings,
					],
					source: importedQuery.source,
					query: importedQuery.domain,
					sourceUrl: sourceUrl.trim() || reconQueryUrl(importedQuery),
					retrievedAt: observedAt,
					scopeRevision:
						project.plan?.status === "approved"
							? project.plan.revision
							: undefined,
				};
			}
			onSave(result, notes);
			setContent("");
			setNotes("");
			setManualError("");
		} catch (error) {
			recordFailure(project.id, {
				phase: "recon",
				stage: "Importar evidencia manual",
				source: kind,
				target: queryLabel || undefined,
				scopeRevision: project.plan?.revision,
				error: error instanceof Error ? error.message : "No se pudo guardar.",
			});
			setManualError(
				error instanceof Error ? error.message : "No se pudo guardar.",
			);
		}
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-base">Recopilar información</CardTitle>
				<CardDescription>
					DNS, certificados, registro y evidencia previa, con trazabilidad por
					proyecto.
				</CardDescription>
			</CardHeader>
			<CardContent>
				{failedQuery && (
					<Alert className="mb-5">
						<AlertDescription className="grid gap-3">
							<p>
								La consulta no produjo evidencia. Puedes continuar con DNS del
								mismo objetivo o registrar información manual.
							</p>
							<div className="flex flex-wrap gap-2">
								<Button
									variant="outline"
									disabled={busy}
									onClick={() => {
										setTab("public");
										updateQuery({
											...failedQuery,
											source: "dns",
											subdomains: false,
										});
									}}
								>
									Continuar con DNS
								</Button>
								<Button
									variant="outline"
									disabled={busy}
									onClick={() => {
										setTab("manual");
										setQueryLabel(failedQuery.domain);
									}}
								>
									Registrar evidencia manual
								</Button>
							</div>
						</AlertDescription>
					</Alert>
				)}
				<Tabs value={tab} onValueChange={setTab}>
					<TabsList className="mb-5 h-auto w-full flex-wrap justify-start">
						<TabsTrigger value="public">
							Consultas de reconocimiento
						</TabsTrigger>
						<TabsTrigger value="manual">Carga manual / JSON</TabsTrigger>
					</TabsList>
					<TabsContent value="public" className="grid gap-5">
						<fieldset disabled={busy} className="grid min-w-0 gap-5">
							<div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_120px]">
								<div className="grid gap-2">
									<label htmlFor="recon-source" className="text-xs font-medium">
										Fuente de reconocimiento
									</label>
									<Select
										value={query.source}
										onValueChange={(source) =>
											updateQuery({
												source: source as ReconQuery["source"],
												subdomains: source === "crtsh",
											})
										}
										disabled={busy}
									>
										<SelectTrigger id="recon-source" className="w-full">
											<SelectValue />
										</SelectTrigger>
										<SelectContent>
											<SelectItem value="crtsh" disabled={ipTarget}>
												Certificados · crt.sh
											</SelectItem>
											<SelectItem value="rdap" disabled={ipTarget}>
												Registro · RDAP
											</SelectItem>
											<SelectItem value="dns">
												{ipTarget
													? "DNS inverso · PTR"
													: "DNS · registros / inverso (PTR)"}
											</SelectItem>
											<SelectItem value="tls">
												TLS · certificado del servicio (activo)
											</SelectItem>
										</SelectContent>
									</Select>
								</div>
								<PlanField
									label="Dominio o IP autorizada"
									value={query.domain}
									onChange={(domain) => updateQuery({ domain })}
									placeholder="empresa.com o 172.16.10.24"
								/>
								<PlanField
									label="Timeout (s)"
									value={query.timeoutSeconds}
									type="number"
									min={5}
									max={60}
									onChange={(seconds) =>
										updateQuery({ timeoutSeconds: Number(seconds) })
									}
								/>
							</div>
							{ipTarget && (
								<p className="m-0 text-xs text-muted-foreground">
									IP detectada: puedes consultar DNS inverso (PTR) o el
									certificado TLS del servicio desde Kali. crt.sh y RDAP solo
									admiten dominios. No se explora la red ni se contactan los
									nombres encontrados.
								</p>
							)}
							{query.source === "tls" && (
								<PlanField
									label="Puerto TLS"
									value={query.port ?? 443}
									type="number"
									min={1}
									max={65535}
									onChange={(port) => updateQuery({ port: Number(port) })}
									hint="TLS directo, por ejemplo HTTPS en 443. No realiza STARTTLS ni autenticación."
								/>
							)}
							{query.source === "crtsh" && (
								<label
									htmlFor="recon-subdomains"
									className="flex items-center gap-3 text-sm"
								>
									<Checkbox
										id="recon-subdomains"
										checked={query.subdomains}
										onCheckedChange={(value) =>
											updateQuery({ subdomains: value === true })
										}
										disabled={busy}
									/>{" "}
									Buscar nombres de subdominios en certificados públicos
								</label>
							)}
							<div className="rounded-lg border bg-background p-4 text-xs leading-relaxed text-muted-foreground">
								{query.source === "dns"
									? ipTarget
										? "Consulta el registro PTR de la IP individual usando los resolvedores configurados en Kali. Puede devolver un nombre interno o no tener registro; no resuelve ni conecta a los nombres encontrados. Requiere el permiso de consultas DNS del plan."
										: "Consulta los siete tipos de registro del nombre exacto desde los resolvedores configurados en Kali. Guarda respuestas y consultas no disponibles; no expande al dominio padre ni conecta a los candidatos."
									: query.source === "tls"
										? ipTarget
											? "Conecta desde Kali a la IP y puerto autorizados sin SNI para leer el certificado TLS; el servidor puede presentar su certificado predeterminado. Comprueba exclusiones y permisos TCP/servicios. No solicita páginas ni sigue nombres SAN."
											: "Conecta desde Kali a una IP IPv4 fijada del host autorizado para leer su certificado TLS. Comprueba las exclusiones y el puerto del plan antes de conectar. No solicita páginas ni sigue nombres SAN."
										: "Las consultas HTTPS se ejecutan en Kali por SSH. Se consulta crt.sh o el registro publicado por IANA; la fuente externa recibe el dominio. Si no puede consultarse, puedes continuar con DNS o carga manual."}
							</div>
							<PlanField
								label={
									externalSource
										? "Comando equivalente · curl"
										: "Referencia CLI en Kali"
								}
								disabled={!externalSource}
								value={command}
								multiline
								placeholder="curl --fail --silent --show-error --max-time 25 'https://crt.sh/?q=empresa.com&output=json'"
								onChange={(text) => {
									setCommand(text);
									try {
										setQuery(parseReconCommand(text));
										setCommandError("");
									} catch (error) {
										setCommandError(
											error instanceof Error
												? error.message
												: "Comando inválido.",
										);
									}
								}}
								hint={
									externalSource
										? "Los campos y el comando se sincronizan. RDAP usa IANA en la app y rdap.org en el equivalente CLI."
										: "Configura esta consulta con los campos. La referencia CLI es orientativa; la app aplica un timeout global y valida el alcance antes de ejecutarla por SSH."
								}
							/>
							{commandError && (
								<Alert variant="destructive">
									<AlertDescription>{commandError}</AlertDescription>
								</Alert>
							)}
							{issues.length > 0 && (
								<Alert>
									<AlertDescription>
										<ul className="m-0 list-disc pl-4">
											{issues.map((issue) => (
												<li key={issue}>{issue}</li>
											))}
										</ul>
									</AlertDescription>
								</Alert>
							)}
							<Button
								className="w-fit"
								disabled={
									!kaliReady ||
									busy ||
									!!commandError ||
									issues.length > 0 ||
									(project.recon?.evidence.length ?? 0) >= 100
								}
								onClick={() => void onQuery(query)}
							>
								{busy ? (
									<LoaderCircle className="size-4 animate-spin" />
								) : (
									<Play className="size-4" />
								)}{" "}
								{busy ? "Consultando fuente…" : "Consultar y guardar evidencia"}
							</Button>
							{!kaliReady && (
								<Alert>
									<AlertDescription className="space-y-3">
										<p>
											Comprueba la conexión global a Kali para ejecutar las
											consultas.
										</p>
										<KaliConnectionButton />
									</AlertDescription>
								</Alert>
							)}
						</fieldset>
					</TabsContent>
					<TabsContent value="manual" className="grid gap-5">
						<fieldset disabled={busy} className="grid min-w-0 gap-5">
							<div className="grid gap-4 sm:grid-cols-2">
								<div className="grid gap-2">
									<label
										htmlFor="recon-import-kind"
										className="text-xs font-medium"
									>
										Formato de evidencia
									</label>
									<Select value={kind} onValueChange={setKind} disabled={busy}>
										<SelectTrigger id="recon-import-kind" className="w-full">
											<SelectValue />
										</SelectTrigger>
										<SelectContent>
											<SelectItem value="manual">
												Lista de activos / notas
											</SelectItem>
											<SelectItem value="crtsh">JSON de crt.sh</SelectItem>
											<SelectItem value="rdap">JSON de RDAP</SelectItem>
										</SelectContent>
									</Select>
								</div>
								<PlanField
									label={
										kind === "manual"
											? "Título de la evidencia"
											: "Dominio consultado en el JSON"
									}
									value={queryLabel}
									onChange={setQueryLabel}
								/>
								<PlanField
									label="Fuente / URL (opcional)"
									value={sourceUrl}
									onChange={setSourceUrl}
									placeholder="https://fuente.example.org/documento"
								/>
								<PlanField
									label="Fecha de la observación"
									value={localDateInput(observedAt)}
									type="datetime-local"
									onChange={(value) => setObservedAt(isoDateInput(value))}
								/>
							</div>
							<PlanField
								label={
									kind === "manual"
										? "Activos candidatos (opcionales)"
										: "Contenido JSON"
								}
								value={content}
								onChange={setContent}
								multiline
								placeholder={
									kind === "manual"
										? "192.168.56.10\napp.empresa.test\n192.168.56.0/24"
										: "Pega la respuesta JSON de la fuente"
								}
								hint={
									kind === "manual"
										? "IP, CIDR o nombres exactos, separados por líneas. Guardar una observación no autoriza un escaneo."
										: "Se guardan nombres y datos seleccionados; se omite el JSON crudo. Se limita el resultado a 500 candidatos."
								}
							/>
							<PlanField
								label="Contexto y notas de la evidencia"
								value={notes}
								onChange={setNotes}
								multiline
								hint="Describe lo observado, su confianza y las limitaciones. Evita credenciales y datos personales innecesarios."
							/>
							<p className="m-0 text-xs text-muted-foreground">
								La carga manual no realiza solicitudes de red. Guarda antes de
								salir; el texto sin guardar se descarta al cambiar de página o
								proyecto.
							</p>
							{manualError && (
								<Alert variant="destructive">
									<AlertDescription>{manualError}</AlertDescription>
								</Alert>
							)}
							<Button
								className="w-fit"
								disabled={
									busy ||
									!queryLabel.trim() ||
									(!content.trim() && !notes.trim()) ||
									(project.recon?.evidence.length ?? 0) >= 100
								}
								onClick={saveManual}
							>
								<Save className="size-4" />
								Guardar evidencia
							</Button>
						</fieldset>
					</TabsContent>
				</Tabs>
			</CardContent>
		</Card>
	);
}
