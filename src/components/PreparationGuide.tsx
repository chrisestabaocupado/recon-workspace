import { Link } from "@tanstack/react-router";
import { ArrowRight, Check, Copy, Terminal } from "lucide-react";
import { type ReactNode, useState } from "react";
import { KaliExecutionCard } from "./KaliConnection";
import { Alert, AlertDescription } from "./ui/alert";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";

function Command({ label, command }: { label: string; command: string }) {
	const [copied, setCopied] = useState(false);
	const [error, setError] = useState(false);
	async function copy() {
		try {
			await navigator.clipboard.writeText(command);
			setCopied(true);
			setError(false);
		} catch {
			setError(true);
		}
	}
	return (
		<div className="min-w-0 overflow-hidden rounded-lg border bg-background">
			<div className="flex items-center justify-between gap-2 border-b px-3 py-2">
				<span className="flex items-center gap-2 text-xs text-muted-foreground">
					<Terminal className="size-3.5" />
					{label}
				</span>
				<Button
					variant="ghost"
					size="xs"
					onClick={() => void copy()}
					aria-label={`Copiar comandos: ${label}`}
				>
					{copied ? <Check /> : <Copy />}
					{copied ? "Copiado" : "Copiar"}
				</Button>
			</div>
			<pre className="m-0 overflow-x-auto p-4 text-xs leading-6">
				<code>{command}</code>
			</pre>
			{error && (
				<output className="block px-4 pb-3 text-xs text-destructive">
					No se pudo copiar. Selecciona el comando y cópialo manualmente.
				</output>
			)}
		</div>
	);
}

function Step({
	number,
	title,
	children,
}: {
	number: number;
	title: string;
	children: ReactNode;
}) {
	return (
		<Card id={`paso-${number}`} className="scroll-mt-6">
			<CardHeader>
				<CardTitle className="flex items-center gap-3 text-base">
					<span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/15 text-sm text-primary">
						{number}
					</span>
					{title}
				</CardTitle>
			</CardHeader>
			<CardContent className="space-y-4 text-sm leading-relaxed text-muted-foreground">
				{children}
			</CardContent>
		</Card>
	);
}

const tools = [
	[
		"Node.js",
		"Servidor de la app y runner remoto",
		"App: 22.12 o superior · Kali: 22 o superior",
	],
	[
		"OpenSSH + SFTP",
		"Autenticación por clave y transferencia del runner",
		"Servicio SSH activo en Kali; SFTP habilitado",
	],
	[
		"Nmap",
		"Enumeración de hosts, puertos y servicios",
		"Integrado · debe estar en el PATH de Kali",
	],
	[
		"HTTPS / Node.js fetch",
		"Consultas a crt.sh y RDAP",
		"Integrado · salida HTTPS y resolución DNS desde Kali",
	],
	[
		"curl",
		"Preparación y comprobaciones manuales de HTTPS",
		"Auxiliar · no sustituye el runner de la app",
	],
	[
		"dig / OpenSSL",
		"Comprobaciones manuales de DNS y certificados TLS",
		"Opcionales · la app utiliza DNS y TLS de Node.js",
	],
];

export function PreparationGuide() {
	return (
		<div className="space-y-6">
			<div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
				<Card>
					<CardHeader>
						<CardTitle className="text-base">
							Tu estación y el ejecutor
						</CardTitle>
					</CardHeader>
					<CardContent className="space-y-4 text-sm text-muted-foreground">
						<div className="flex flex-wrap items-center gap-3 rounded-lg bg-muted/50 p-4 text-foreground">
							<span>App en Windows o Kali</span>
							<ArrowRight className="size-4 text-primary" />
							<span>SSH por clave</span>
							<ArrowRight className="size-4 text-primary" />
							<span>Pruebas en Kali</span>
						</div>
						<p>
							La guía prepara el entorno global y sirve para todos los
							proyectos. Los comandos se ejecutan manualmente en la terminal
							indicada; los botones Copiar no los ejecutan.
						</p>
						<p>
							Necesitas acceso a la consola de Kali, un usuario con permisos
							para instalar paquetes y conectividad entre el servidor de la app
							y Kali. Si usas una VM, configura una red accesible o el reenvío
							del puerto SSH. La VPN y las rutas hacia los objetivos deben estar
							en Kali.
						</p>
					</CardContent>
				</Card>
				<KaliExecutionCard />
			</div>
			<Step number={1} title="Instalar y comprobar las herramientas en Kali">
				<p>
					En el equipo que aloja la app instala Node.js 22.12 o superior. Desde
					la carpeta del proyecto ejecuta los siguientes comandos y abre
					http://127.0.0.1:3000; mantén el servidor activo mientras utilizas el
					workspace.
				</p>
				<Command
					label="Servidor de la app · carpeta del proyecto"
					command={"node --version\nnpm install\nnpm run dev"}
				/>
				<p>
					En la consola de Kali instala los requisitos. Verifica que el sistema
					sea Kali y que Node.js sea 22 o superior; si el paquete disponible es
					anterior, instala una versión compatible siguiendo la documentación
					oficial de Node.js.
				</p>
				<Command
					label="Kali · Bash"
					command={
						"sudo apt update\nsudo apt install openssh-server nmap nodejs curl ca-certificates bind9-dnsutils openssl\ncat /etc/os-release\nnode --version\nnmap --version\ncommand -v node nmap dig openssl"
					}
				/>
				<p>
					El usuario SSH debe poder escribir en su directorio personal: la app
					sube allí el runner mediante SFTP. Para empezar usa un perfil Nmap de
					conexión TCP (-sT); las opciones que requieren privilegios pueden
					fallar con un usuario normal. La app no eleva permisos con sudo
					automáticamente.
				</p>
			</Step>
			<Step number={2} title="Activar SSH e identificar el servidor">
				<Command
					label="Kali · Bash"
					command={
						"sudo systemctl enable --now ssh\nsystemctl status ssh --no-pager\nip -br address\nwhoami\nsudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256"
					}
				/>
				<p>
					Anota la IP accesible, el usuario y el puerto (22 por defecto). Obtén
					la huella SHA256 desde la consola de Kali o un canal confiable. Si SSH
					presenta otra clave de host, compara la huella de su archivo público
					correspondiente en /etc/ssh. Conserva el valor para verificarlo al
					conectar.
				</p>
				<p>
					Permite el puerto SSH en el firewall y la red de la VM desde el equipo
					que aloja la app. Para Reconocimiento, Kali también necesita resolver
					DNS y salir por HTTPS a las fuentes públicas.
				</p>
			</Step>
			<Step number={3} title="Crear la clave y autorizarla en Kali">
				<p>
					Crea la clave en el equipo que ejecuta el servidor de la app.
					Sustituye USUARIO_KALI e IP_KALI en los ejemplos. Usa un nombre nuevo
					si ya existe pentest_kali y conserva la clave privada en ese equipo.
				</p>
				<Tabs defaultValue="windows">
					<TabsList>
						<TabsTrigger value="windows">Windows · PowerShell</TabsTrigger>
						<TabsTrigger value="linux">Linux · Bash</TabsTrigger>
					</TabsList>
					<TabsContent value="windows" className="space-y-3">
						<Command
							label="Servidor de la app · PowerShell"
							command={
								'New-Item -ItemType Directory -Force "$env:USERPROFILE\\.ssh"\nssh-keygen -t ed25519 -f "$env:USERPROFILE\\.ssh\\pentest_kali"\nGet-Content "$env:USERPROFILE\\.ssh\\pentest_kali.pub"'
							}
						/>
						<p>
							Si ssh-keygen no está disponible, instala el Cliente OpenSSH desde
							Características opcionales de Windows.
						</p>
					</TabsContent>
					<TabsContent value="linux">
						<Command
							label="Servidor de la app · Bash"
							command={
								"mkdir -p ~/.ssh\nchmod 700 ~/.ssh\nssh-keygen -t ed25519 -f ~/.ssh/pentest_kali\ncat ~/.ssh/pentest_kali.pub"
							}
						/>
					</TabsContent>
				</Tabs>
				<p>
					Copia la línea pública completa que empieza por ssh-ed25519. En la
					consola de Kali, como el usuario que utilizarás para SSH, prepara el
					archivo y añade esa línea al final con el editor:
				</p>
				<Command
					label="Kali · Bash · usuario SSH"
					command={
						"mkdir -p ~/.ssh\nchmod 700 ~/.ssh\ntouch ~/.ssh/authorized_keys\nchmod 600 ~/.ssh/authorized_keys\nnano ~/.ssh/authorized_keys"
					}
				/>
				<p>
					Guarda y sal del editor. La clave pública termina en .pub; la ruta que
					pide la app es la de la clave privada, sin .pub. Si elegiste una frase
					de contraseña al generarla, introdúcela después en la configuración
					SSH.
				</p>
			</Step>
			<Step number={4} title="Probar el acceso desde el servidor de la app">
				<p>
					Compara la huella del primer contacto con la obtenida en Kali antes de
					aceptar. Estos ejemplos usan el puerto 22; cámbialo si configuraste
					otro. El resultado debe mostrar Node.js 22 o superior y la versión de
					Nmap sin pedir la contraseña del usuario Kali.
				</p>
				<Tabs defaultValue="windows">
					<TabsList>
						<TabsTrigger value="windows">Windows · PowerShell</TabsTrigger>
						<TabsTrigger value="linux">Linux · Bash</TabsTrigger>
					</TabsList>
					<TabsContent value="windows">
						<Command
							label="Servidor de la app · PowerShell"
							command={
								'Test-NetConnection IP_KALI -Port 22\nssh -p 22 -i "$env:USERPROFILE\\.ssh\\pentest_kali" USUARIO_KALI@IP_KALI "node --version && nmap --version"'
							}
						/>
					</TabsContent>
					<TabsContent value="linux">
						<Command
							label="Servidor de la app · Bash"
							command={
								'ssh -p 22 -i ~/.ssh/pentest_kali USUARIO_KALI@IP_KALI "node --version && nmap --version"'
							}
						/>
					</TabsContent>
				</Tabs>
				<p>
					La app usa sesiones sin una terminal interactiva. Si Node.js funciona
					al abrir una terminal pero este comando falla, corrige el PATH de las
					sesiones SSH no interactivas, especialmente si instalaste Node.js con
					un gestor de versiones.
				</p>
			</Step>
			<Step number={5} title="Configurar y verificar la conexión en la app">
				<ol className="list-decimal space-y-2 pl-5">
					<li>
						Abre <strong className="text-foreground">Configurar Kali</strong>{" "}
						desde el encabezado o la tarjeta de esta página.
					</li>
					<li>
						Completa host, puerto, usuario y la ruta absoluta de la clave
						privada en el servidor de la app. En Windows, por ejemplo:
						C:\Users\usuario\.ssh\pentest_kali.
					</li>
					<li>
						Introduce la frase de contraseña de la clave si tiene una y pulsa{" "}
						<strong className="text-foreground">
							Comprobar SSH y herramientas
						</strong>
						.
					</li>
					<li>
						En el primer contacto compara la huella observada con la de Kali,
						confirma la comparación, pulsa{" "}
						<strong className="text-foreground">Aceptar huella</strong> y vuelve
						a comprobar.
					</li>
					<li>
						Confirma que aparece{" "}
						<strong className="text-foreground">Kali verificado</strong>. El
						diagnóstico comprueba Kali Linux, Node.js y Nmap; la conectividad
						hacia las fuentes y objetivos se comprueba por separado.
					</li>
				</ol>
				<Alert>
					<AlertDescription>
						La verificación dura 15 minutos. Repite la comprobación al caducar,
						recargar, reiniciar el servidor o cambiar la configuración. La frase
						de contraseña permanece en memoria; host, usuario, ruta y huella se
						guardan en este navegador.
					</AlertDescription>
				</Alert>
			</Step>
			<Step number={6} title="Preparar el proyecto y comenzar las pruebas">
				<ol className="list-decimal space-y-2 pl-5">
					<li>
						Crea el proyecto en Alcance y planificación; registra la
						autorización, activos permitidos, exclusiones y ventana de
						ejecución. Completa y aprueba el plan en la app.
					</li>
					<li>
						Comprueba en Kali la VPN, las rutas y el acceso a los destinos
						permitidos. Para las consultas públicas de Reconocimiento registra
						también el permiso pasivo en el plan.
					</li>
					<li>
						En Enumeración agrega los objetivos, selecciona un perfil compatible
						con los permisos del usuario y aplica los límites del plan al
						comando. Confirma el alcance e inicia dentro de la ventana acordada.
					</li>
					<li>
						Revisa los resultados y descarga los XML antes de reiniciar el
						servidor. Exporta los datos del proyecto para conservar una copia
						fuera del navegador.
					</li>
				</ol>
				<Button asChild>
					<Link to="/alcance">
						Ir a Alcance y planificación
						<ArrowRight />
					</Link>
				</Button>
			</Step>
			<Card>
				<CardHeader>
					<CardTitle className="text-base">
						Herramientas que utiliza este workspace
					</CardTitle>
				</CardHeader>
				<CardContent>
					<div className="overflow-x-auto">
						<table className="data-table w-full text-left text-sm">
							<caption className="sr-only">
								Herramientas, usos y requisitos actuales
							</caption>
							<thead>
								<tr className="border-b">
									<th className="p-3">Herramienta</th>
									<th className="p-3">Uso</th>
									<th className="p-3">Requisito / estado</th>
								</tr>
							</thead>
							<tbody>
								{tools.map(([name, purpose, status]) => (
									<tr key={name} className="border-b last:border-0">
										<th scope="row" className="p-3 font-medium">
											{name}
										</th>
										<td className="p-3 text-muted-foreground">{purpose}</td>
										<td className="p-3 text-muted-foreground">{status}</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</CardContent>
			</Card>
			<Card>
				<CardHeader>
					<CardTitle className="text-base">Si algo falla</CardTitle>
				</CardHeader>
				<CardContent className="space-y-3 text-sm">
					{[
						[
							"Conexión rechazada o tiempo agotado",
							"Comprueba la IP, el puerto, el servicio ssh, el firewall y la red o reenvío de puertos de la VM. La conexión sale del servidor de la app.",
						],
						[
							"Permission denied (publickey)",
							"Revisa el usuario, la clave privada elegida, su frase de contraseña y la línea pública de authorized_keys. El directorio .ssh y el archivo deben pertenecer al usuario SSH y tener permisos 700 y 600.",
						],
						[
							"No se puede leer la clave privada",
							"Usa una ruta que exista en el servidor de la app y que pueda leer el usuario que ejecuta Node.js. No uses el archivo .pub ni una ruta que solo exista en Kali si la app corre en Windows.",
						],
						[
							"La huella no coincide",
							"Comprueba en la consola de Kali si cambió la máquina o su clave de host. Actualiza la huella únicamente después de verificar el nuevo valor por un canal confiable.",
						],
						[
							"Node.js, Nmap o SFTP no disponibles",
							"Repite las comprobaciones desde una sesión SSH no interactiva. Instala las versiones requeridas, corrige el PATH y comprueba que el servidor SSH permita SFTP y escritura en el directorio del usuario.",
						],
						[
							"Nmap requiere privilegios o la fuente HTTPS falla",
							"Usa un perfil TCP connect si el usuario carece de privilegios. Para fuentes públicas revisa DNS, certificados, proxy y salida HTTPS de Kali; una conexión SSH verificada no garantiza acceso a la fuente.",
						],
					].map(([title, description]) => (
						<details key={title} className="rounded-lg border p-3">
							<summary className="font-medium">{title}</summary>
							<p className="mb-0 mt-3 leading-relaxed text-muted-foreground">
								{description}
							</p>
						</details>
					))}
					<p className="pt-2 text-xs text-muted-foreground">
						Documentación oficial:{" "}
						<a
							className="text-primary underline"
							href="https://www.kali.org/docs/general-use/ssh-configuration/"
							target="_blank"
							rel="noreferrer"
						>
							SSH en Kali
						</a>{" "}
						·{" "}
						<a
							className="text-primary underline"
							href="https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement"
							target="_blank"
							rel="noreferrer"
						>
							Claves SSH en Windows
						</a>{" "}
						·{" "}
						<a
							className="text-primary underline"
							href="https://nodejs.org/en/download"
							target="_blank"
							rel="noreferrer"
						>
							Instalar Node.js
						</a>
					</p>
				</CardContent>
			</Card>
		</div>
	);
}
