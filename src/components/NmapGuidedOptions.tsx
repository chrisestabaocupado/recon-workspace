import { useEffect, useId, useState } from "react";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import { Checkbox } from "#/components/ui/checkbox";
import { Input } from "#/components/ui/input";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import { Textarea } from "#/components/ui/textarea";
import type { NmapConfig } from "#/lib/nmap";
import { nmapOptions } from "#/lib/nmap";
import {
	type GuidedPorts,
	type GuidedProtocol,
	getGuidedPorts,
	getGuidedProtocol,
	setGuidedPorts,
	setGuidedProtocol,
} from "#/lib/nmap-guided";

const goals = [
	{
		id: "web",
		title: "Comprobar servicios web",
		description:
			"HTTP y HTTPS en 80 y 443 TCP, con identificación del servicio.",
	},
	{
		id: "quick",
		title: "Buscar puertos habituales",
		description: "Revisión rápida de los 100 puertos TCP más frecuentes.",
	},
	{
		id: "service",
		title: "Identificar servicios",
		description:
			"Revisa los 1.000 puertos TCP más frecuentes e identifica sus versiones.",
	},
	{
		id: "discovery",
		title: "Solo descubrir equipos",
		description: "Busca hosts activos. No enumera sus puertos ni servicios.",
	},
] as const;

const guidedIds = new Set([
	"syn-scan",
	"connect-scan",
	"udp-scan",
	"ports",
	"fast",
	"service-version",
	"ping-scan",
	"list-scan",
	"skip-discovery",
]);

export function NmapGuidedOptions({
	config,
	command,
	profile,
	onProfile,
	onChange,
	onTargets,
	onAdvanced,
}: {
	config: NmapConfig;
	command: string;
	profile: string;
	onProfile: (profile: string) => void;
	onChange: (config: NmapConfig) => void;
	onTargets: (text: string) => void;
	onAdvanced: () => void;
}) {
	const id = useId();
	const targetValue = config.targets.join("\n");
	const [targetText, setTargetText] = useState(targetValue);
	useEffect(() => {
		setTargetText((current) => {
			const normalized = current
				.split(/[\n,\s]+/)
				.filter(Boolean)
				.join("\n");
			return normalized === targetValue ? current : targetValue;
		});
	}, [targetValue]);
	const discoveryOnly = Boolean(
		config.values["ping-scan"] || config.values["list-scan"],
	);
	const protocol = getGuidedProtocol(config);
	const ports = getGuidedPorts(config);
	const advancedOptions = nmapOptions.filter(
		(option) =>
			!guidedIds.has(option.id) &&
			config.values[option.id] !== undefined &&
			config.values[option.id] !== false,
	);
	function toggleOption(key: string, checked: boolean) {
		const values = { ...config.values };
		if (checked) values[key] = true;
		else delete values[key];
		onChange({ ...config, values });
	}
	return (
		<div className="space-y-6 p-6">
			<section aria-labelledby={`${id}-goal`}>
				<h3 id={`${id}-goal`} className="mb-1 text-sm font-semibold">
					1. ¿Qué quieres comprobar?
				</h3>
				<p className="mb-3 text-xs text-muted-foreground">
					Elige una plantilla y luego ajústala. Al elegir otra se reemplazan las
					opciones de escaneo; se mantienen los objetivos y los límites del
					plan.
				</p>
				<div className="grid gap-2 sm:grid-cols-2">
					{goals.map((goal) => (
						<Button
							key={goal.id}
							variant="outline"
							aria-pressed={profile === goal.id}
							onClick={() => onProfile(goal.id)}
							className={`h-auto items-start justify-start whitespace-normal px-4 py-3 text-left ${profile === goal.id ? "border-primary bg-primary/5" : ""}`}
						>
							<span>
								<span className="block text-sm font-medium">{goal.title}</span>
								<span className="mt-1 block text-xs font-normal leading-relaxed text-muted-foreground">
									{goal.description}
								</span>
							</span>
						</Button>
					))}
				</div>
			</section>
			<div className="grid gap-5 lg:grid-cols-2">
				<div className="space-y-2">
					<label htmlFor={`${id}-targets`} className="text-sm font-semibold">
						2. ¿Qué equipos?
					</label>
					<Textarea
						id={`${id}-targets`}
						className="min-h-24 font-mono text-xs"
						value={targetText}
						placeholder="192.168.1.10 o servidor.ejemplo"
						onChange={(event) => {
							setTargetText(event.target.value);
							onTargets(event.target.value);
						}}
					/>
					<p className="text-xs text-muted-foreground">
						IP, nombre DNS o red CIDR autorizada. Separa varios con espacios o
						saltos de línea.
					</p>
				</div>
				<div className="space-y-3">
					<h3 className="text-sm font-semibold">3. ¿Cómo comprobarlos?</h3>
					{discoveryOnly ? (
						<div className="rounded-lg border bg-muted/20 p-4 text-xs text-muted-foreground">
							Solo se buscarán equipos activos. Para revisar servicios, elige
							una de las plantillas de puertos.
						</div>
					) : (
						<>
							<div className="space-y-1.5">
								<label
									htmlFor={`${id}-protocol`}
									className="text-xs font-medium"
								>
									Tipo de servicio
								</label>
								<Select
									value={protocol}
									onValueChange={(value) =>
										onChange(setGuidedProtocol(config, value as GuidedProtocol))
									}
								>
									<SelectTrigger id={`${id}-protocol`} className="w-full">
										<SelectValue />
									</SelectTrigger>
									<SelectContent>
										{protocol === "advanced" && (
											<SelectItem value="advanced" disabled>
												Técnica avanzada (conservada)
											</SelectItem>
										)}
										<SelectItem value="tcp">
											TCP · web, SSH, bases de datos
										</SelectItem>
										<SelectItem value="udp">
											UDP · DNS, SNMP y otros servicios
										</SelectItem>
										<SelectItem value="both">
											TCP + UDP · ambos protocolos
										</SelectItem>
									</SelectContent>
								</Select>
								<p className="text-xs text-muted-foreground">
									Para HTTP/HTTPS usa TCP. UDP no comprueba esos servicios y
									puede tardar más. Al cambiar el tipo se reemplaza la técnica
									anterior por TCP Connect, UDP o ambos.
								</p>
							</div>
							<div className="space-y-1.5">
								<label htmlFor={`${id}-ports`} className="text-xs font-medium">
									Puertos a revisar
								</label>
								<Select
									value={ports}
									onValueChange={(value) =>
										onChange(setGuidedPorts(config, value as GuidedPorts))
									}
								>
									<SelectTrigger id={`${id}-ports`} className="w-full">
										<SelectValue />
									</SelectTrigger>
									<SelectContent>
										{ports === "advanced" && (
											<SelectItem value="advanced" disabled>
												Selección avanzada (conservada)
											</SelectItem>
										)}
										<SelectItem value="common">
											100 más frecuentes · rápido
										</SelectItem>
										<SelectItem value="default">
											1.000 más frecuentes · estándar
										</SelectItem>
										<SelectItem value="all">
											Todos · 1–65535, más lento
										</SelectItem>
										<SelectItem value="custom">
											Elegir puertos concretos
										</SelectItem>
									</SelectContent>
								</Select>
								{ports === "custom" && (
									<Input
										aria-label="Puertos concretos"
										className="font-mono text-xs"
										value={String(config.values.ports ?? "")}
										placeholder="80,443,8080 o 8000-8100"
										onChange={(event) =>
											onChange({
												...config,
												values: { ...config.values, ports: event.target.value },
											})
										}
									/>
								)}
								<p className="text-xs text-muted-foreground">
									Solo se revisan los puertos seleccionados. Si la web usa 8080
									u otro puerto, inclúyelo aquí.
									{ports === "custom" &&
										!config.values.ports &&
										" Sin una lista explícita se usa la selección estándar de Nmap."}
								</p>
							</div>
							<label
								htmlFor={`${id}-versions`}
								className="flex items-start gap-2 text-xs leading-relaxed"
							>
								<Checkbox
									id={`${id}-versions`}
									checked={Boolean(
										config.values["service-version"] ||
											config.values.aggressive,
									)}
									disabled={Boolean(config.values.aggressive)}
									onCheckedChange={(checked) =>
										toggleOption("service-version", checked === true)
									}
								/>
								Identificar el servicio y su versión (puede tardar más)
							</label>
						</>
					)}
					{!discoveryOnly && (
						<label
							htmlFor={`${id}-discovery`}
							className="flex items-start gap-2 text-xs leading-relaxed"
						>
							<Checkbox
								id={`${id}-discovery`}
								checked={Boolean(config.values["skip-discovery"])}
								onCheckedChange={(checked) =>
									toggleOption("skip-discovery", checked === true)
								}
							/>
							Omitir descubrimiento previo: intentar el escaneo aunque el equipo
							no responda a las sondas de descubrimiento
						</label>
					)}
				</div>
			</div>
			{(advancedOptions.length > 0 || config.unknown.length > 0) && (
				<div className="rounded-lg border p-3 text-xs">
					<p className="mb-2 text-muted-foreground">
						Opciones adicionales activas: cambiar de vista no las elimina. Los
						controles solo reemplazan las opciones que modificas. Revísalas en
						Avanzado.
					</p>
					<div className="flex flex-wrap gap-1.5">
						{advancedOptions.map((option) => (
							<Badge key={option.id} variant="secondary">
								{option.label}
							</Badge>
						))}
						{config.unknown.length > 0 && (
							<Badge variant="warning">Argumentos sin mapear</Badge>
						)}
					</div>
				</div>
			)}
			<div className="rounded-lg border bg-muted/20 p-4">
				<div className="mb-2 flex flex-wrap items-center justify-between gap-2">
					<span className="text-xs font-medium">Comando que se ejecutará</span>
					<Button size="sm" variant="ghost" onClick={onAdvanced}>
						Editar en Avanzado
					</Button>
				</div>
				<code className="block whitespace-pre-wrap break-all text-xs">
					{command}
				</code>
				<p className="mb-0 mt-2 text-xs text-muted-foreground">
					Nada se ejecuta al elegir una plantilla. Revisa el alcance y confirma
					la autorización antes de iniciar.
				</p>
			</div>
		</div>
	);
}
