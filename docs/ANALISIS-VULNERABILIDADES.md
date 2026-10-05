# Análisis de vulnerabilidades

Primera versión implementada el 2 de octubre de 2026. Ruta: `/analisis`.

## Flujo

1. Seleccionar un proyecto. El resumen toma las observaciones Nmap guardadas en Enumeración, usando la última observación de cada IP, puerto y protocolo. Cada servicio muestra fecha y ejecución de origen. Los servicios cerrados se excluyen; no se reutiliza su versión antigua. El historial conserva diez ejecuciones, por lo que el resumen puede ser incompleto.
2. Revisar productos y versiones pendientes. Según el servicio, la interfaz propone consultas de SearchSploit/cve-search y verificaciones HTTP o TLS. Una biblioteca interna no se deduce de un banner: requiere archivos o inventario de paquetes.
3. Configurar y verificar Kali en el navbar. **Comprobar herramientas** consulta los binarios disponibles y la API local de cve-search. Es una instantánea, no instala herramientas.
4. Elegir la recomendación de un servicio o completar una consulta en Herramientas. Revisar el comando y ejecutar explícitamente. Las consultas bibliográficas no contactan al objetivo; Nikto y testssl.sh sí lo hacen.
5. Revisar candidatas, ajustar severidad y recomendación, y documentar la validación. Confirmar requiere una nota de evidencia. Una coincidencia por versión no acredita aplicabilidad: revisar rangos, condiciones, configuración y parches del proveedor, incluidos backports.
6. Descargar el reporte completo y exportar JSON/Markdown para conservar evidencia. También se pueden importar reportes o registrar observaciones manuales sin Kali.

## Adaptadores

La casilla **Usar HTTPS** también ajusta los puertos habituales: activar cambia 80 → 443; desactivar cambia 443 → 80. Conserva puertos personalizados como 8080 y 8443. El comando y las comprobaciones del alcance se actualizan con el nuevo puerto.

Al cambiar manualmente al puerto 80 se selecciona HTTP; al cambiar a 443, HTTPS. La casilla **Usar HTTPS** permite ajustar esa selección y los otros puertos conservan el protocolo elegido. Se fuerza el protocolo con `-ssl`/`-nossl`. Revisa el protocolo observado antes de ejecutar Nikto. Su `-maxtime` reserva quince segundos dentro del timeout (mínimo un segundo de prueba); cinco segundos antes del corte final se solicita `SIGINT` si sigue activo para guardar JSON. El límite final mantiene `SIGKILL` si no cierra. Un timeout corto puede cortar durante la inicialización, sin reporte. Se desactiva la comprobación de actualizaciones con `-nocheck`. Se recoge tanto el nombre exacto del reporte como el nombre con `.json` adicional que produce Nikto 2.6. Si falta el archivo o está vacío, se conserva el diagnóstico original y la salida se descarga como texto, sin interpretarla como cero vulnerabilidades. El diagnóstico descargable y guardado en la evidencia conserva hasta los últimos 8.000 caracteres de consola. Un código cero con `FAIL`, errores o terminación anticipada también genera una incidencia; los elementos `FAIL` no se convierten en vulnerabilidades.

| Adaptador | Entrada | Resultado y límites |
| --- | --- | --- |
| SearchSploit | Producto/versión o CVE | Archivo local de Exploit-DB, salida JSON `RESULTS_EXPLOIT`. Busca referencias, no ejecuta exploits. No es un catálogo completo de CVE; la búsqueda textual puede tener falsos positivos. |
| cve-search | CVE o proveedor/producto CPE | API de Kali en `http://127.0.0.1:5000/api`. Admite entradas `id`, `summary`, `cvss`. La búsqueda del producto devuelve candidatas sin filtrar automáticamente por versión. Usar identificadores de la base, por ejemplo proveedor `apache` y producto `http_server`. |
| Nikto | IP, dominio exacto o URL HTTP/HTTPS, con ruta opcional | JSON `vulnerabilities`. Perfil `-Tuning 123b`: archivos interesantes, configuración, información e identificación de software. Sin seguimiento de redirecciones, sin actualizaciones/submisiones automáticas y con pausa de un segundo entre pruebas. Para dominios se conservan Host/SNI y se fija la conexión a una IP validada en Kali. |
| testssl.sh | Una IP TCP y puerto con TLS directo | JSON plano `--jsonfile`; conserva observaciones distintas de OK/INFO/DEBUG como candidatas. STARTTLS y SNI personalizado no están implementados. |
| Trivy | Ruta absoluta de una carpeta en Kali | `trivy fs`, únicamente vulnerabilidades, con bases locales y actualizaciones/búsquedas remotas deshabilitadas. Admite reportes JSON Trivy importados, incluidos los generados externamente para imágenes. El adaptador de ejecución no descarga imágenes ni analiza repositorios remotos. |

Los reportes incompatibles o JSON incompletos producen una incidencia y conservan la salida del runner para revisión manual. Un fallo o cero coincidencias no significa ausencia de vulnerabilidades. Los hallazgos de verificaciones activas también empiezan como candidatas.

## Preparación de Kali y bases

La aplicación necesita el acceso SSH ya existente, Kali Linux, Node.js 22 o superior y Nmap para la verificación global. Además, los adaptadores necesitan sus propios binarios y datos. Internet en Kali puede usarse para prepararlos fuera del módulo; las consultas del módulo permanecen locales.

- SearchSploit pertenece al paquete `exploitdb`. Instalarlo/actualizarlo con el gestor de paquetes de Kali y revisar `searchsploit -h`. La comprobación informa la modificación del archivo `/usr/share/exploitdb/files_exploits.csv` cuando existe; esta fecha no garantiza la actualidad de todos los registros.
- Nikto pertenece al paquete `nikto`; testssl.sh al paquete `testssl.sh`, cuyo ejecutable en Kali es `testssl`. Las versiones y opciones deben verificarse en la instalación real.
- Instalar y preparar [cve-search](https://github.com/cve-search/cve-search) siguiendo su documentación, cargar su base y habilitar su API **local** en el puerto 5000 de Kali. La app no provisiona MongoDB, no descarga el catálogo y no consulta la API pública. **Comprobar herramientas** consulta `dbInfo` para mostrar los metadatos disponibles. Si el esquema difiere, importar evidencia manual y conservar el original.
- Para Trivy, preparar sus bases antes de desconectar, siguiendo su [guía de entornos sin Internet](https://trivy.dev/docs/v0.55/advanced/air-gap/). El adaptador usa `--offline-scan`, `--skip-db-update`, `--skip-java-db-update`, `--skip-check-update` y `--skip-version-check`. Una base ausente, incompatible o caducada puede hacer fallar la consulta; no se descarga automáticamente.
- No se integra `vulners` en este flujo porque consulta una API externa.

Referencias de los adaptadores: [SearchSploit en Kali](https://www.kali.org/tools/exploitdb/), [Nikto en Kali](https://www.kali.org/tools/nikto/), [testssl.sh en Kali](https://www.kali.org/tools/testssl.sh/), [API cve-search](https://www.cve-search.org/api/), [CLI Trivy](https://www.trivy.dev/docs/latest/guide/references/configuration/cli/trivy_filesystem/).

## Alcance y ejecución

Nikto y testssl.sh requieren permiso específico en **Alcance → Reglas** y una nueva aprobación del plan. Los planes antiguos conservan su aprobación pero no reciben esos permisos. Se verifica en cliente y servidor: estado, aprobación, campos obligatorios, ventana, timeout, destino incluido/no excluido y puerto permitido. Se ejecuta un solo objetivo por operación. testssl.sh conserva la restricción a IP; Nikto admite también dominios y URLs HTTP/HTTPS. No se admiten rangos ni listas.

Para Nikto, pegar `https://webmail.imcpbdc.com.ve/webmail/` selecciona HTTPS y puerto 443; la ruta se pasa como `-root`. Un dominio sin esquema usa el puerto y protocolo del formulario. Editar estos controles también actualiza una URL completa. Se rechazan credenciales, parámetros, fragmentos y otros protocolos. El dominio exacto debe estar incluido en el plan: autorizar solo su IP no autoriza todos sus hosts virtuales. El dominio y las exclusiones DNS se resuelven en Kali; se rechaza cualquier dirección excluida, respuesta inválida o exclusión que no pueda resolverse. Como en la enumeración, un dominio incluido autoriza sus IP resueltas salvo exclusiones explícitas. Se prefiere una IP IPv4 si está disponible y se fija el destino TCP mediante un proxy temporal limitado a ese host/puerto en loopback de Kali. Nikto conserva el dominio en Host/SNI y no necesita volver a resolverlo. El proxy no sigue redirecciones ni conecta a otros destinos y se cierra al terminar. La evidencia registra la IP fijada. Antes de enviar pruebas, se vuelve a validar la ventana después de la resolución DNS.

Validación de URL: regresiones para protocolo/puerto/ruta, inclusiones exactas, exclusiones IP y DNS, respuestas de resolución incompletas y programa autocontenido para SSH. Pruebas HTTP y CONNECT comprueban que el proxy no conecta a otros hosts o puertos y devuelve la redirección sin seguirla. Una prueba adicional con Nikto 2.6.0 real, dominio ficticio sin DNS y servidor HTTPS en loopback confirmó Host, SNI y ruta `/webmail/`, con conexión fijada a `127.0.0.1`. `npm run test:nikto` incluye esta prueba. No se volvió a escanear el webmail del usuario durante el desarrollo.

El límite de paquetes/s existente es propio de Nmap. Estos adaptadores tienen ritmo propio y su permiso explica esa limitación: Nikto pausa un segundo entre pruebas y testssl.sh no impone un máximo de paquetes/s. Si el compromiso exige ese límite para todas las herramientas, mantener esos permisos desactivados e importar evidencia obtenida bajo los controles acordados.

Los argumentos se envían como datos por stdin a un programa fijo; `spawn` no usa shell. Las operaciones son exclusivas de Kali, con huella SSH fijada y verificación vigente. El runner usa un directorio temporal privado, elimina reportes temporales al terminar y limita salida/tiempo. Trivy no hereda variables `TRIVY_*` de Kali ni usa un archivo de configuración del directorio analizado. El tiempo consumido en conectar SSH se descuenta del presupuesto.

Solo puede existir una operación de análisis simultánea por servidor. Timeout configurable de 5–180 segundos, más hasta diez segundos de cierre/transporte. El timeout termina el grupo de procesos de la herramienta. La navegación interna espera la respuesta; una recarga puede perderla y deja una incidencia de resultado sin confirmar. Esta versión no tiene cancelación interactiva ni seguimiento recuperable de la herramienta tras recargar: si se activa una condición de parada, detenerla en Kali y revisar los procesos antes de reanudar. Una desconexión no acredita terminación remota.

## Evidencias, retención y exportación

- Datos en el workspace del navegador; importación/exportación global conserva análisis y compatibilidad con proyectos antiguos.
- Hasta 30 evidencias y 500 hallazgos por proyecto; al alcanzar el límite se pide exportar y eliminar evidencias antiguas, sin borrar silenciosamente revisiones.
- Runner: reporte máximo de 2 MB. Se interpreta completo cuando es válido; la copia persistida se recorta a 50.000 caracteres con aviso. La descarga completa permanece en memoria hasta la siguiente ejecución o cierre de página. Importación manual: archivo hasta 60 KB y texto hasta 60.000 caracteres.
- Persisten herramienta, consulta, fecha de captura, identidad del ejecutor, revisión del plan, salida, advertencias, errores y relaciones hallazgo/evidencia. La fecha de importación no sustituye a la fecha de ejecución: registrar esta última en procedencia.
- Los intentos repetidos conservan evidencia separada; no se deduplican automáticamente hallazgos ni se sobrescriben revisiones.
- Eliminar una evidencia elimina también sus hallazgos asociados, con confirmación. La retención acordada sigue siendo manual.
- Se aplica la depuración habitual de credenciales antes de persistir/exportar. Revisar el contenido de reportes personalizados antes de compartirlos.
- JSON global permite restaurar datos desde los controles existentes de importación del workspace. Markdown contiene inventario, hallazgos, evidencia e incidencias de análisis.

## Validación

Pruebas automatizadas con datos ficticios y procesos simulados: permisos específicos y compatibilidad de planes, límites de alcance, inventario con observaciones recientes, cinco formatos de reporte, persistencia y referencias, confirmación con evidencia, argumentos sin shell, modo local Trivy, UTF-8, timeout y falta de herramientas. La suite existente comprueba el transporte SSH y la vinculación/caducidad de la verificación.

La regresión de Nikto comprueba nombre exacto de salida y extensión adicional de 2.6, JSON vacío, errores con código cero, elementos `FAIL`, evidencia parcial y cierre SIGINT/SIGKILL. `npm run test:nikto` ejecuta una prueba adicional con Nikto real instalado en PATH y OpenSSL: crea servidores HTTP/HTTPS temporales en `127.0.0.1`, lee reportes, interpreta hallazgos, valida persistencia y verifica el cierre antes del corte final. No usa objetivos externos. Requiere Node con soporte para `--experimental-strip-types` y las dependencias habituales de Nikto. Para validar otra instalación, `NIKTO_SCRIPT` admite la ruta a `nikto.pl` (se ejecuta mediante Perl).

Auditoría inicial del 2 de octubre de 2026: el archivo de consola aportado por el usuario mostró conexión HTTP a OpenResty, pero no cierre ni reporte. Se reprodujo la extensión adicional con Nikto 2.6.0 oficial y se corrigió la recogida. Referencia: [selección del nombre de archivo en Nikto 2.6.0](https://github.com/sullo/nikto/blob/2.6.0/program/plugins/nikto_core.plugin) y [escritura de JSON al cierre](https://github.com/sullo/nikto/blob/2.6.0/program/plugins/nikto_report_json.plugin). En esa auditoría Host/SNI de dominio estaba pendiente; la ampliación posterior añade URL y dominio con conexión fijada.

Resultado de la auditoría: 97 pruebas automatizadas aprobadas; TypeScript, Biome y build correctos. Tres pruebas de integración con Nikto 2.6.0 real aprobadas en Ubuntu/WSL, usando dependencias extraídas en un directorio temporal, sin instalar paquetes del sistema: HTTP hasta recogida y persistencia de evidencia, cierre con SIGINT conservando JSON, y HTTPS con certificado generado para el servidor local. Se mantuvo el límite de tiempo del adaptador. Esta validación no sustituye la aceptación del transporte SSH en la Kali del usuario ni verifica el webmail real.

Validación de interfaz: creación de un proyecto ficticio en un origen de navegador separado, importación de una muestra cve-search, registro de candidata y evidencia, edición de una nota y recuperación de ambas tras recargar. Captura: [hallazgo de prueba](screenshots/analisis-validacion.jpg). La muestra no representa una vulnerabilidad detectada en un objetivo real.

Pendiente de aceptación en Kali real: disponibilidad/versiones de los cinco adaptadores, configuración y esquema de cve-search, bases Trivy/Exploit-DB, pruebas Nikto y TLS de un servicio de laboratorio incluido en el plan, timeout remoto y exportación del reporte completo. No se ejecutaron escaneos contra objetivos del usuario durante el desarrollo.
