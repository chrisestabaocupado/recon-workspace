# Panel de enumeración

Interfaz local de enumeración de redes para ejecutar Nmap exclusivamente en Kali por SSH, con la aplicación alojada en Windows o en Kali.

## Estado de esta entrega

La primera versión implementa un flujo de Nmap: proyecto y objetivos, ejecución por SSH con configuración global en el navbar, perfiles, editor bidireccional con autocompletado, logs, cancelación confirmada, timeout, descarga de XML e importación de reportes XML/texto al inventario local. El catálogo incluye 112 opciones con controles; opciones adicionales se conservan con un aviso en los argumentos avanzados. La cobertura completa contra una versión Nmap concreta sigue pendiente de verificar.

La ejecución conserva los argumentos del comando actual y su proyecto original. Un proveedor global mantiene el seguimiento entre páginas y guarda una referencia para recuperarlo tras recargar mientras el servidor siga activo. Si el servidor pierde el trabajo o SSH no confirma su terminación, se muestra un estado desconocido.

La navegación está separada por rutas para las fases de alcance, reconocimiento, enumeración, análisis, explotación, post-explotación e informe. Alcance y planificación administra proyectos y reglas; Reconocimiento recopila certificados públicos, RDAP y evidencia manual con revisión de candidatos; Enumeración ejecuta Nmap aplicando el plan. Análisis organiza el inventario, consultas y evidencias; Explotación, Post-explotación e Informe quedan pendientes. La interfaz usa tema oscuro fijo con una paleta en negro, blanco y grises. El verde identifica estados exitosos o verificados; el amarillo identifica resultados parciales, advertencias y errores que requieren atención. Los estados conservan sus etiquetas de texto; las acciones y categorías usan colores neutros.

Consulta [Alcance y planificación](docs/ALCANCE-PLANIFICACION.md) para el flujo y las comprobaciones que aplica el MVP. Antes de una ejecución de red es necesario un plan aprobado y un comando dentro de sus límites. La autorización real y sus datos deben completarse por el operador.

Consulta [Reconocimiento](docs/RECONOCIMIENTO.md) para fuentes, filtros, sincronización curl, trazabilidad y límites. Las consultas públicas necesitan permiso pasivo explícito en el plan; la carga manual no hace solicitudes de red. Las consultas HTTPS de crt.sh y RDAP salen de Kali mediante SSH. Los futuros adaptadores activos siguen pendientes.

Consulta [Análisis de vulnerabilidades](docs/ANALISIS-VULNERABILIDADES.md) para el resumen del inventario, recomendaciones por servicio, consultas locales SearchSploit/cve-search, verificaciones Nikto/testssl.sh, análisis de archivos con Trivy, revisión de hallazgos y evidencias. Las bases y herramientas se preparan en Kali; las coincidencias se registran como candidatas. Nikto y testssl.sh requieren permisos específicos en el plan. Falta validar estos adaptadores contra una instalación Kali real.

BloodHound y los adaptadores de enumeración DNS/SMB/LDAP todavía no están implementados. La conexión SSH está preparada, pero requiere validar el flujo con una instancia Kali y una clave configuradas por el usuario.

## Requisitos

- Node.js 22.12 o superior para la aplicación; Node.js 22 o superior para el runner en Kali. Las pruebas se han ejecutado con Node.js 24.
- Kali Linux con Nmap y Node.js 22 o superior. Se comprueba la distribución antes de habilitar pruebas.
- Acceso SSH por clave desde el servidor de la aplicación a Kali. Kali necesita acceso HTTPS a las fuentes públicas para Reconocimiento.

## Desarrollo

```sh
npm install
npm run dev
```

Abre `http://127.0.0.1:3000`. El servidor de desarrollo queda vinculado a localhost.

## Uso desde Windows con Kali

La página **Preparación del entorno** (`/preparacion`) aparece encima de las fases y reúne los pasos para instalar herramientas, activar SSH, crear y autorizar claves desde Windows o Linux, comparar la huella y verificar el ejecutor. Incluye comandos copiables, requisitos actuales y soluciones a errores habituales. La configuración utiliza el mismo diálogo SSH global del resto de la aplicación.

1. Inicia la aplicación en Windows con `npm run dev`.
2. En el navbar de cualquier página abre **Configurar Kali** y proporciona host, usuario, ruta local a la clave y, si corresponde, su frase de contraseña.
3. Comprueba la conexión. En el primer contacto compara la huella SHA-256 mostrada con una fuente confiable de la máquina Kali; acéptala explícitamente y vuelve a comprobar.
4. En **Alcance y planificación**, crea el proyecto, completa el compromiso y registra la aprobación obtenida fuera de la app.
5. En **Enumeración**, agrega los destinos permitidos, selecciona los parámetros y aplica explícitamente los límites del plan al comando. Confirma el alcance e inicia dentro de la ventana acordada.

La configuración SSH se comparte entre todas las fases. Cada operación abre una sesión con la huella fijada; no existe ejecución local ni alternativa automática en tu PC. Al recargar, se comprueba automáticamente la configuración guardada si está completa y tiene una huella aceptada. La verificación dura 15 minutos, se vincula a todos los campos de conexión y se renueva automáticamente al caducar. Si falla, se muestra el motivo y se espera un reintento manual. Un cambio de host o puerto borra la huella anterior. Las operaciones ya iniciadas mantienen su ejecutor original. La frase de una clave cifrada permanece solo en memoria: después de recargar puede ser necesario introducirla de nuevo. No se persisten tokens ni se acepta automáticamente una huella nueva.

La ruta de clave corresponde a la máquina Windows que ejecuta el servidor de la app. El runner remoto se copia al directorio del usuario en Kali y ejecuta Nmap con una lista de argumentos, sin construir una orden de shell a partir del texto escrito.

## Datos locales

Las páginas de Reconocimiento y Enumeración incluyen un checklist por proyecto con último resultado, pendientes e historial de intentos por revisión del plan; permite copiar o descargar el checklist. Conserva hasta 500 resultados por proyecto y reconstruye los datos ya guardados. También incluyen un registro persistente de incidencias, con botones para copiarlo o descargarlo. La exportación JSON conserva los errores y el informe Markdown de Reconocimiento también los incluye. Se retienen las últimas 300 incidencias por proyecto y 300 sin proyecto; los intentos previos no registrados no se recuperan automáticamente.

Proyectos, objetivos, configuración de conexión (sin claves privadas ni frases de contraseña) e historial compacto se guardan en el `localStorage` del perfil del navegador. Usa **Exportar** e **Importar** para trasladarlos entre Kali y Windows. Las importaciones JSON se validan y admiten hasta 5 MB; los errores de cuota se muestran y los datos corruptos se conservan hasta que el usuario decida reemplazarlos.

Cada proyecto conserva las últimas diez ejecuciones con un extracto de hasta 7.000 caracteres. Los logs del servidor retienen hasta 1.500.000 caracteres y muestran un aviso cuando la salida es parcial. El XML se captura por separado, desde `-oX -`, `-oX archivo.xml` o `-oA base`, hasta 8 MB; archivos mayores o rutas con plantillas de fecha se descargan directamente del ejecutor. Descarga los XML disponibles antes de reiniciar el servidor: los trabajos y artefactos viven en memoria.

Comandos persistidos, logs y XML descargados depuran argumentos NSE y patrones habituales de credenciales. Esta depuración no sustituye una revisión de reportes de scripts personalizados. La frase de contraseña SSH permanece solo en memoria del navegador. Eliminar los datos del navegador elimina esa copia local.

## Validación

```sh
npm test
npx tsc --noEmit
npm run check
npm run build
```

Las pruebas cubren CLI, importación, secretos, asociación de historial, estados, bloqueo de ejecución local, caducidad y vinculación de la verificación, transporte SSH y HTTPS remoto con procesos controlados. No ejecutan escaneos de red. Consulta [la validación del MVP](docs/VALIDACION-MVP.md) para resultados y la prueba de aceptación pendiente en Kali.

## Arquitectura y alcance

- TanStack Start + TypeScript.
- Interfaz basada en shadcn/ui, con CodeMirror para el editor de comandos.
- Persistencia en el navegador; no hay base de datos.
- El catálogo vive en `src/lib/nmap-options.ts`; el parser y generador en `src/lib/nmap-command.ts`, reexportados por `src/lib/nmap.ts`. El seguimiento global vive en `WorkspaceProvider` y el ciclo de procesos en `src/server/job-manager.ts`.
- Consulta [la especificación del MVP](docs/MVP-enumeracion.md) para el alcance completo y las etapas.


