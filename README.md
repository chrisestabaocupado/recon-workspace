# Recon workspace — reconocimiento y mapeo

Interfaz local para reconocer activos, mapear hosts, puertos y servicios y generar informes por proyecto. Ejecuta Nmap y consultas de reconocimiento exclusivamente en Kali por SSH, con la aplicación alojada en Windows o en Kali. No incluye análisis de vulnerabilidades, explotación ni postexplotación.

## Estado de esta entrega

La primera versión implementa un flujo de Nmap: proyecto y objetivos, ejecución por SSH con configuración global en el navbar, perfiles, editor bidireccional con autocompletado, logs, cancelación confirmada, timeout, descarga de XML e importación de reportes XML/texto al inventario local. El catálogo incluye 112 opciones con controles; opciones adicionales se conservan con un aviso en los argumentos avanzados. La cobertura completa contra una versión Nmap concreta sigue pendiente de verificar.

La ejecución conserva los argumentos del comando actual y su proyecto original. Un proveedor global mantiene el seguimiento entre páginas y guarda una referencia para recuperarlo tras recargar mientras el servidor siga activo. Si el servidor pierde el trabajo o SSH no confirma su terminación, se muestra un estado desconocido.

El flujo consta de cuatro etapas: **Alcance y planificación → Reconocimiento → Enumeración y mapeo → Informes**. Alcance administra proyectos y reglas; Reconocimiento recopila DNS, certificados TLS, certificados públicos, RDAP y evidencia manual con revisión de candidatos; Enumeración ejecuta Nmap aplicando el plan. Informes consolida los datos guardados, sin realizar consultas de red, con vista previa, descarga Markdown, copia e impresión para guardar como PDF. La interfaz usa tema oscuro fijo; la impresión utiliza fondo blanco y excluye menús y controles.

Consulta [Alcance y planificación](docs/ALCANCE-PLANIFICACION.md) para el flujo y las comprobaciones que aplica el MVP. Antes de una ejecución de red es necesario un plan aprobado y un comando dentro de sus límites. La autorización real y sus datos deben completarse por el operador.

Consulta [Reconocimiento](docs/RECONOCIMIENTO.md) para fuentes, filtros, sincronización curl, trazabilidad y límites. Desde la interfaz se puede consultar DNS inverso (PTR) y certificados TLS de IP individuales IPv4/IPv6, incluidas IP privadas accesibles desde Kali. DNS y las consultas públicas necesitan permiso pasivo explícito; TLS necesita permisos TCP/servicios y puerto autorizado. crt.sh y RDAP solo admiten dominios. Todo se ejecuta en Kali por SSH; la carga manual no hace solicitudes de red.

Consulta [Informes](docs/INFORMES.md) para contenido, exportación, trazabilidad y limitaciones. Se ha eliminado el módulo de análisis y sus adaptadores, rutas y pruebas exclusivas. Al cargar o importar un workspace antiguo se descartan sus datos de análisis y permisos específicos; se conservan los proyectos, planes, reconocimiento, ejecuciones Nmap e incidencias de las fases vigentes. Exporta una copia con la versión anterior si necesitas conservar el análisis retirado.

Los adaptadores adicionales SMB/LDAP y BloodHound no forman parte de esta entrega. La conexión SSH requiere validar el flujo con una instancia Kali y una clave configuradas por el usuario. El diagnóstico ya no solicita herramientas ni bases de vulnerabilidades; dig y OpenSSL son auxiliares opcionales para comprobaciones manuales (la app consulta DNS y TLS mediante Node.js).

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
5. En **Enumeración y mapeo**, agrega los destinos permitidos, selecciona los parámetros y aplica explícitamente los límites del plan al comando. Confirma el alcance e inicia dentro de la ventana acordada.
6. En **Informes**, selecciona el proyecto, revisa el inventario consolidado y descarga Markdown o pulsa **Imprimir / PDF** y elige **Guardar como PDF** en el navegador.

La configuración SSH se comparte entre todas las fases. Cada operación abre una sesión con la huella fijada; no existe ejecución local ni alternativa automática en tu PC. Al recargar, se comprueba automáticamente la configuración guardada si está completa y tiene una huella aceptada. La verificación dura 15 minutos, se vincula a todos los campos de conexión y se renueva automáticamente al caducar. Si falla, se muestra el motivo y se espera un reintento manual. Un cambio de host o puerto borra la huella anterior. Las operaciones ya iniciadas mantienen su ejecutor original. La frase de una clave cifrada permanece solo en memoria: después de recargar puede ser necesario introducirla de nuevo. No se persisten tokens ni se acepta automáticamente una huella nueva.

La ruta de clave corresponde a la máquina Windows que ejecuta el servidor de la app. El runner remoto se copia al directorio del usuario en Kali y ejecuta Nmap con una lista de argumentos, sin construir una orden de shell a partir del texto escrito.

El botón **Terminal** del navbar abre un shell interactivo en ese mismo Kali, con la configuración SSH verificada. Al cerrar el diálogo se desconecta su sesión. Es una consola manual: los comandos no se validan contra el plan ni se incorporan a los informes. Consulta [Terminal remota](docs/TERMINAL.md) para uso, límites y precauciones.

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
- Consulta [la especificación inicial del MVP](docs/MVP-enumeracion.md) como referencia histórica; el alcance vigente es reconocimiento, mapeo e informes, según este README.


