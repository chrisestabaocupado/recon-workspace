import { Link } from "@tanstack/react-router";
import { ArrowRight, CircleDashed, ShieldCheck } from "lucide-react";
import { PhasePage } from "#/components/PhasePage";
import { Badge } from "#/components/ui/badge";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "#/components/ui/card";

const details: Record<
	string,
	{
		description: string;
		purpose: string;
		next: string;
		nextPath: "/" | "/alcance";
	}
> = {
	"Alcance y planificación": {
		description:
			"Define las reglas y los activos autorizados antes de iniciar una evaluación.",
		purpose:
			"Aquí se organizarán los proyectos, ventanas de prueba, exclusiones y contactos de emergencia.",
		next: "Ir a Enumeración",
		nextPath: "/",
	},
	Reconocimiento: {
		description:
			"Reúne información inicial sobre los dominios y activos incluidos en el alcance.",
		purpose:
			"Esta fase incorporará descubrimiento de DNS, dominios y fuentes públicas con evidencia asociada al proyecto.",
		next: "Revisar el alcance",
		nextPath: "/alcance",
	},
	"Análisis de vulnerabilidades": {
		description:
			"Revisa los servicios y versiones observados para priorizar verificaciones posteriores.",
		purpose:
			"Se mostrarán hallazgos como observaciones verificables, con origen, evidencia y prioridad revisable.",
		next: "Abrir Enumeración",
		nextPath: "/",
	},
	Explotación: {
		description:
			"Fase reservada para pruebas explícitas, acotadas y autorizadas.",
		purpose:
			"Esta página es solo estructura de navegación. No ejecuta exploits ni acciones sobre objetivos.",
		next: "Volver al alcance",
		nextPath: "/alcance",
	},
	"Post-explotación": {
		description:
			"Documenta validaciones posteriores únicamente cuando estén autorizadas en el plan de pruebas.",
		purpose:
			"La fase pendiente organizará evidencia y acciones manuales dentro del alcance aprobado.",
		next: "Volver al alcance",
		nextPath: "/alcance",
	},
	Informe: {
		description:
			"Consolida el alcance, las ejecuciones, observaciones y evidencia recolectada.",
		purpose:
			"La exportación de informes se añadirá después de normalizar los resultados de las fases anteriores.",
		next: "Abrir Enumeración",
		nextPath: "/",
	},
};

export function PhasePlaceholder({ title }: { title: keyof typeof details }) {
	const phase = details[title];
	return (
		<PhasePage title={title} description={phase.description}>
			<Card>
				<CardHeader>
					<div className="mb-2 flex items-center gap-2">
						<Badge variant="outline">
							<CircleDashed className="mr-1 size-3" />
							En planificación
						</Badge>
					</div>
					<CardTitle className="flex items-center gap-2 text-base">
						<ShieldCheck className="size-4 text-primary" />
						Propósito de esta fase
					</CardTitle>
					<CardDescription>{phase.purpose}</CardDescription>
				</CardHeader>
				<CardContent>
					<Link
						to={phase.nextPath}
						className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
					>
						{phase.next}
						<ArrowRight className="size-4" />
					</Link>
				</CardContent>
			</Card>
		</PhasePage>
	);
}
