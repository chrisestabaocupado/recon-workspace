# Validación del MVP de enumeración

Última actualización: 2 de octubre de 2026. Alcance: revisión del código actual, compilación, tipos, arranque compilado, rutas HTTP y comprobaciones de funciones con datos sintéticos. No se ejecutaron escaneos de red ni conexiones a Kali.

## Estado después de las correcciones

Se corrigieron los bloqueos de comando, cancelación y seguimiento, además de validación de importaciones, depuración de credenciales y captura de XML. La UI ejecuta los argumentos del comando actual, bloquea borradores inválidos y preserva orden, repeticiones y el separador `--`. La cancelación espera la salida del proceso; timeout y desconexiones tienen estados explícitos. Un proveedor global sigue los trabajos entre páginas y recupera su ID tras recargar, con una instantánea del proyecto original.

Los reportes XML/texto se pueden importar y el XML de una ejecución se descarga por separado del log. Se indica truncamiento; los límites son 1.500.000 caracteres de log, 8 MB de XML y 5 MB de JSON. El historial conserva diez ejecuciones por proyecto. El catálogo tiene 112 entradas; sigue pendiente certificar cobertura completa para una versión Nmap concreta.

| Comprobación posterior | Resultado |
| --- | --- |
| `npm test` | 56/56 pruebas correctas: CLI, alcance, reconocimiento, secretos, trabajos, SSH verificado y HTTPS remoto con datos simulados |
| `npx tsc --noEmit` | Correcto |
| `npm run check` | Correcto, sin desactivar reglas |
| `npm run build` | Correcto, cliente y servidor; runner incluido en el bundle |
| Siete rutas en la compilación, puerto temporal 3100 | HTTP 200, tema oscuro y sidebar; servidor temporal detenido |
| Runner con procesos simulados | Finalización, cancelación, EOF y timeout; se verifica que el hijo ya no existe |
| Artefactos simulados | XML desde stdout/archivo, UTF-8 entre chunks y respeto del separador `--` |
| Interacción visual en navegador | Siete navbars, modal, validación de puerto, continuidad al navegar y pérdida de frase al recargar, verificados |
| Aplicación en Windows/Kali → SSH → Kali | Pendiente con Kali real; ejecución local eliminada |

Actualización de planificación: `/alcance` ahora administra el compromiso de prueba y conserva revisiones previas. La política de aprobación, activos/exclusiones, técnicas, ventana, puertos, tasa y duración se aplica en cliente y servidor. DNS se resuelve en el ejecutor y se fija la IP comprobada. Se verificaron formulario, prioridad de exclusiones, fechas, persistencia tras recarga y bloqueo de un borrador en una vista de prueba con otro origen (`127.0.0.1:3100`); no se registró una autorización real ni se ejecutaron escaneos. La suite suma 32 pruebas. Detalles y límites en [Alcance y planificación](ALCANCE-PLANIFICACION.md).

Para la primera prueba real faltan Kali con Node/Nmap, acceso SSH por clave y el objetivo autorizado de laboratorio. Para cerrar todos los criterios del MVP aún faltan cobertura CLI versionada, mayor separación de los paneles de Enumeración y los adaptadores posteriores. No se presenta el MVP completo como aceptado hasta validar el recorrido real.

Actualización de reconocimiento: `/reconocimiento` incluye crt.sh, RDAP vía IANA, evidencia manual/JSON, candidatos deduplicados, revisión, promoción dentro del alcance y exportación Markdown/JSON. Permisos, fuentes y respuestas se validan antes de guardar. La suite suma 46 pruebas; la UI se comprobó con datos sintéticos, persistencia tras recarga y descarga del Markdown. Las fuentes externas se probaron con respuestas simuladas; falta validarlas con un dominio autorizado. Detalles en [Reconocimiento](RECONOCIMIENTO.md).


Actualización de ejecución global: el navbar de las siete fases abre un modal SSH compartido. Enumeración y las consultas HTTPS de Reconocimiento exigen Kali por SSH; no hay lanzamiento local de Nmap, resolución local de objetivos ni fetch local a fuentes. El diagnóstico remoto comprueba Kali Linux, Node.js 22+ y Nmap, prepara el runner y entrega una verificación temporal en memoria vinculada a todos los campos. Expira a los 15 minutos; recargar, cambiar datos o reiniciar exige comprobar nuevamente. La huella se valida en cada sesión SSH y cambiar host/puerto la borra.

La suite actual suma 56 pruebas, incluidas diez sobre rechazo del modo local, verificación/credenciales/caducidad, diagnóstico Kali, separación de shell y stdin, cierre/abort de SSH, respuestas HTTPS y persistencia sin secretos. Nmap valida el acceso verificado incluso en diagnósticos; los guardas del plan siguen vigentes. La identidad del ejecutor acompaña historial y evidencias, sin token, frase ni ruta privada. Se mantienen compatibles los registros antiguos.

Se verificaron en la compilación las siete páginas y el modal con el navegador integrado, sin errores de consola. En el origen aislado 127.0.0.1:3100 se usaron exclusivamente campos sintéticos: un puerto inválido fue rechazado antes de leer una clave o intentar SSH; datos y frase en memoria sobrevivieron a navegación interna, cambiar puerto borró la huella y recargar vació la frase. Se limpiaron esos campos y se detuvo el servidor de prueba. La aplicación compilada queda en 127.0.0.1:3000. Captura: [modal SSH global](screenshots/kali-global-ssh.jpg). El cambio de viewport del navegador integrado no se aplicó: no se afirma validación móvil.

No se realizó una conexión real ni un escaneo; deben verificarse SSH, rutas/permisos del ejecutor, disponibilidad de las fuentes y primera prueba contra el laboratorio autorizado.

El resto del documento conserva la auditoría inicial para dejar registro de los defectos que motivaron estas correcciones. Las descripciones siguientes se refieren al estado anterior.

## Dictamen de la auditoría inicial

Existe una base navegable para enumeración con Nmap, tema oscuro, siete rutas de fases, formularios, autocompletado, persistencia local y un ejecutor local/SSH. Todavía no es un MVP fiable de extremo a extremo: falta corregir la fidelidad del comando, el ciclo de ejecución/cancelación y la continuidad entre páginas, y validar una conexión Kali real.

La primera prueba debe concentrarse en una única VM de laboratorio y unos pocos puertos TCP. Las páginas de reconocimiento, análisis, explotación, post-explotación e informe son estructura de navegación, no módulos operativos. Alcance tampoco dispone de su propio flujo: hoy los proyectos se administran dentro de Enumeración.

## Evidencia de la auditoría inicial

| Comprobación | Resultado |
| --- | --- |
| `npm run build` | Correcto, cliente y servidor |
| `npx tsc --noEmit` | Correcto |
| `npm run start` en puerto temporal 3100 | Inicio correcto y página principal HTTP 200; proceso temporal detenido al terminar |
| Las siete rutas en desarrollo | HTTP 200; HTML con clase `dark` y navegación de fases |
| Conversión de un comando Nmap común | Conserva los valores, aunque normaliza el orden de opciones |
| Comillas sin cerrar | Tokenizador rechaza la entrada; la UI no bloquea por ese error el botón de ejecución |
| Resultado de texto sintético | Identifica host, estado y puertos abiertos/cerrados |
| Importación de proyecto JSON incompleto | Acepta `projects: [{}]`; falta validación de estructura |
| Secreto sintético en argumentos NSE | Se conserva en el JSON exportado; falta depuración de secretos |
| Runner con `--version` | Emite `spawn nmap ENOENT`: Nmap no está disponible en el PATH de esta máquina Windows |
| `npm run check` | Falla: 66 errores, 24 advertencias y 1 aviso; incluye formato, imports y esquema Biome desactualizado |
| Ejecución SSH real, XML en navegador y cancelación remota | Pendientes de validación; no existe una conexión Kali configurada para esta revisión |

## Bloqueos identificados en la auditoría inicial

### 1. El comando visible debe coincidir con lo que se ejecuta

En [nmap.ts](../src/lib/nmap.ts) se reprodujeron estos casos:

- `nmap -v0 192.0.2.10` se reconstruye como `nmap -v 192.0.2.10`.
- `nmap -d9 192.0.2.10` se reconstruye como `nmap -ddd 192.0.2.10`.
- `sudo nmap -sT -p 80 192.0.2.10` agrega `sudo` y `nmap` como objetivos.
- `nmap -- -example` pierde el separador `--`.
- `nmap -p -sV 192.0.2.10` consume `-sV` como valor de puertos y no informa el error de aridad.

En [index.tsx](../src/routes/index.tsx), `runScan` ejecuta la configuración reconstruida, mientras el editor puede conservar otro texto. Si el texto nuevo tiene comillas sin cerrar, continúa disponible la configuración anterior y el botón no considera `commandError`.

Corrección requerida: distinguir errores bloqueantes de avisos de opciones avanzadas; conservar tokens y semántica; identificar prefijos o sintaxis no soportada; validar valores requeridos; mostrar el comando efectivo antes de iniciar. Mantener un único borrador válido, sin ejecutar valores anteriores cuando la entrada actual es inválida.

La documentación de Nmap permite niveles explícitos de depuración hasta `-d9`; limitar el serializador a tres repeticiones cambia su significado. Fuente: [Nmap: salida y niveles de depuración](https://nmap.org/book/man-output.html).

### 2. Cancelación y desconexión con estados verificables

En [jobs.ts](../src/server/jobs.ts), `cancelNmapJob` informa cancelación aunque todavía no exista `job.stop`. Una ejecución remota cancelada durante el establecimiento de SSH puede continuar con la instalación del runner y lanzar Nmap posteriormente. La cancelación remota envía una señal al canal y cierra SSH, pero marca `cancelled` inmediatamente.

En [runner.mjs](../src/server/runner.mjs) no hay manejo de señales que confirme la terminación del proceso Nmap hijo. Por revisión del código, no puede garantizarse que la señal dirigida al runner detenga a Nmap. Este comportamiento requiere reproducción en Kali.

Corrección requerida: estados `iniciando`, `ejecutando`, `cancelación solicitada`, `cancelado`, `fallido` y `desconocido`; cancelación desde el inicio; terminación del hijo y, cuando proceda, grupo de procesos; confirmación de salida; timeout máximo; tratamiento explícito de cortes SSH.

### 3. La ejecución debe sobrevivir al cambio de página

El identificador de ejecución y su seguimiento viven en el estado de la ruta de Enumeración. Al navegar a otra fase o recargar se pierde ese estado; el trabajo permanece en memoria del servidor y no hay una forma de recuperar su seguimiento desde la UI.

Además, el sondeo depende de `command` y `config.targets`: editar durante un trabajo reinicia el offset de lectura a cero y puede duplicar salida. Al completar, el historial se guarda en el proyecto seleccionado en ese momento, utilizando datos del formulario que pueden haber cambiado. La UI de cancelación interrumpe el sondeo antes de guardar el estado final.

Corrección requerida: separar el gestor de ejecuciones de las rutas; guardar ID y metadatos de recuperación en localStorage; fijar proyecto, argumentos, conexión y fechas al iniciar; recuperar el estado desde el servidor; marcar como interrumpido o desconocido cuando el servidor ya no conoce el trabajo.

### 4. Validación real del entorno Kali

Se requiere Node.js, Nmap, SSH por clave, escritura en el home remoto y conectividad hacia la VM objetivo. Comprobar autenticación, huella, carga del runner, ejecución sin privilegios innecesarios, salida, finalización y cancelación. La comprobación de versiones actual no valida todavía toda esa cadena.

## Pendientes identificados en la auditoría inicial

- **Resultados y artefactos:** favorecer XML como salida explícita visible; descargar el XML completo, mostrar errores de interpretación e importar reportes existentes. `-oX archivo.xml` escribe el XML en el ejecutor; actualmente no se recoge ese archivo por SSH. Nmap recomienda XML para integración de software: [documentación oficial](https://nmap.org/book/man-output.html).
- **Límites de salida:** hoy el servidor corta silenciosamente al llegar a 1.500.000 caracteres y el historial retiene un extracto de 7.000. Indicar truncamiento y permitir conservar el reporte íntegro mediante descarga.
- **Proyectos y alcance:** página funcional de Alcance con edición/eliminación, objetivos y exclusiones; mostrar cualquier destino que no coincida con el alcance declarado. Hoy el alcance es texto descriptivo y no se compara con los argumentos ejecutados.
- **Persistencia:** validar cada proyecto, objetivo y resultado al leer/importar; tamaño máximo, datos corruptos, limpieza del historial y tratamiento de cuota. Mantener localStorage y exportaciones JSON sin base de datos.
- **Secretos:** reconocer credenciales en argumentos de scripts y resultados; evitar guardarlas en historial y exportaciones. La frase de contraseña SSH ya se mantiene fuera de localStorage, pero eso no cubre todos los secretos de Nmap/NSE.
- **Cobertura CLI:** revisar todos los parámetros y sus reglas contra una versión Nmap declarada. Hay 111 opciones catalogadas; ese número no demuestra cobertura completa ni compatibilidad con todas las versiones.
- **Modularidad:** extraer de `index.tsx` proyectos, conexiones, borrador de comando, ejecuciones y resultados. Las nuevas rutas por sí solas no separan los estados y responsabilidades de ese componente.
- **Comprobaciones de calidad:** corregir Biome y añadir regresiones centradas en semántica CLI, estado de trabajos, importación y cancelación. El build y TypeScript no cubren esas reglas.

DNS y HTTP/TLS son ampliaciones útiles después del recorrido Nmap. Nikto, SMB/LDAP y BloodHound pueden añadirse como adaptadores posteriores. Implementar explotación o post-explotación no es un requisito para validar el MVP actual de enumeración.

## Primera prueba de aceptación

1. Ejecutar las regresiones automatizadas de comando, cancelación y continuidad antes de iniciar el laboratorio.
2. Preparar Kali y una única VM de laboratorio autorizada; registrar los servicios esperados para comparar resultados.
3. Crear el proyecto, completar su plan, registrar autorización escrita y definir activos, exclusiones, contactos, ventana y límites. Configurar Kali por SSH desde el navbar y comprobar versiones y confianza de la huella.
4. Revisar en el editor un comando limitado como `nmap -sT -sV -Pn -T3 -p 22,80,443 --max-rate 100 --host-timeout 60s -oX - <IP_LAB>`. Sustituir el marcador por la IP real y ajustar puertos, tasa y timeout al plan de laboratorio.
5. Verificar coincidencia entre comando y campos, inicio y finalización, puertos/servicios esperados y estado final.
6. Cambiar de página y recargar durante una ejecución: recuperar seguimiento sin duplicar logs ni asociarlo a otro proyecto.
7. Probar cancelación con una tarea controlada de duración suficiente; confirmar que el proceso remoto termina. Probar además fallo de conexión y ausencia de herramienta.
8. Descargar el XML, exportar el proyecto y volver a importarlo. Confirmar resultados íntegros, historial del proyecto correcto y ausencia de secretos.

Aceptar el MVP inicial cuando estos pasos pasen de extremo a extremo en el modo de ejecución elegido. Para afirmar soporte completo de ambas modalidades se deben repetir con la app alojada en Kali y en Windows, siempre por SSH.

