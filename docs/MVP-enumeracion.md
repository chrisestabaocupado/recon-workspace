# Panel de enumeración — especificación inicial

Fecha: 1 de octubre de 2026.

Estado: recorrido inicial de Nmap implementado para ejecución exclusiva en Kali por SSH, con configuración global en el navbar, con cobertura parcial del catálogo de parámetros. Alcance y planificación administra proyectos y reglas que se aplican a Enumeración. Reconocimiento integra crt.sh, RDAP y evidencia manual con revisión y exportación. Las otras cuatro fases permanecen pendientes. Nikto, BloodHound y los demás módulos siguen en el roadmap; falta validar SSH contra una instalación Kali real.

Consulta [el módulo de planificación](ALCANCE-PLANIFICACION.md) para campos, revisiones, comprobaciones de destinos y límites operativos. La app registra autorizaciones obtenidas fuera de ella. El [módulo de análisis](ANALISIS-VULNERABILIDADES.md) ya implementa resumen de inventario, recomendaciones, consultas locales SearchSploit/cve-search y adaptadores Nikto/testssl.sh/Trivy; su aceptación en Kali real sigue pendiente. Esta ampliación sustituye el estado pendiente de análisis y Nikto descrito en la especificación inicial.

Correcciones verificadas: fidelidad de argumentos CLI, bloqueo de comandos inválidos, seguimiento global entre páginas y recargas, historial ligado al proyecto original, cancelación confirmada y timeout, validación de JSON/cuota, depuración de credenciales y captura/importación/descarga de XML. Consulta [la validación actual](VALIDACION-MVP.md). Las secciones siguientes describen el objetivo completo; no todos sus criterios están implementados todavía.

## Objetivo

Centralizar la enumeración de redes, servicios web y Active Directory en una interfaz web. Ejecutar herramientas en Kali, convertir resultados compatibles en un inventario común y permitir descargar las salidas originales.

El usuario confirmó Kali como entorno de ejecución y Windows como entorno alternativo para iniciar la aplicación y conectarla por SSH a Kali. Confirmó Nmap, BloodHound y Nikto, además de las herramientas necesarias para enumeración.

También requiere cobertura de todos los parámetros de las herramientas integradas y edición bidireccional: campos de formulario que generan el comando y comando pegado/escrito que completa automáticamente los campos correspondientes.

## Formas de uso

1. App en Kali: la aplicación también conecta por SSH al ejecutor Kali configurado; no hay rama de ejecución local. El navegador guarda datos de la UI en su `localStorage`.
2. Remoto: app Node.js en Windows y navegador en Windows; el servidor de la app conecta por SSH a Kali. Windows no necesita instalar herramientas de enumeración ni WSL. Los datos quedan en el navegador donde se usa la app.

La red explorada es siempre la que puede alcanzar Kali, incluidas sus interfaces y VPN. SSH proporciona el canal de control; no hace que Kali tenga acceso automático a las redes de Windows.

En el primer lanzamiento se prioriza uso personal, con la API escuchando en localhost. Si se permite acceso desde otras máquinas, se debe añadir autenticación antes de exponer ejecuciones.

## Flujo de usuario

1. Crear proyecto y definir objetivos, rangos incluidos y exclusiones.
2. Configurar la conexión global a Kali por SSH desde el navbar.
3. Comprobar conexión y disponibilidad/versiones de herramientas.
4. Seleccionar objetivo, tipo de enumeración y perfil.
5. Editar parámetros desde el formulario o pegar/escribir el comando; sincronizar ambos y mostrar el comando efectivo antes de iniciar.
6. Ejecutar trabajo y mostrar salida en vivo.
7. Asociar resultados compactos y referencias a archivos descargables al inventario del proyecto.
8. Proponer siguientes acciones según servicios descubiertos; el usuario elige cuáles ejecutar.
9. Comparar ejecuciones, añadir notas y exportar resultados.

## Pantallas

| Pantalla | Contenido |
| --- | --- |
| Proyectos | Nombre, alcance, exclusiones, notas y última actividad |
| Conexiones | Kali por SSH, estado y herramientas disponibles |
| Objetivos | Hosts, nombres DNS, servicios, URLs y relaciones |
| Nueva ejecución | Formulario y editor de comando sincronizados, objetivo, módulo, perfil, parámetros, límites y validación |
| Ejecución | Log en vivo, estado, duración, cancelación y archivos |
| Detalle de host | Puertos, servicios, versiones, evidencia y acciones sugeridas |
| Active Directory | Dominio, requisitos de recolección, artefactos y enlace a BloodHound |
| Exportación | Inventario JSON/CSV y descarga de salidas originales |

## Catálogo de herramientas

El catálogo es extensible. Cada herramienta integrada debe ofrecer campos para todos los parámetros documentados de su versión compatible, además de sus subcomandos, cuando existan. La cobertura de parámetros y las capacidades de ejecución son conceptos separados: se muestran restricciones de entorno, privilegios o alcance junto a la opción correspondiente. Tener una herramienta registrada no significa ejecutarla automáticamente.

| Área | Herramientas propuestas | Resultado esperado |
| --- | --- | --- |
| Red | Nmap | Hosts, puertos, protocolos y servicios |
| DNS | dig, herramientas DNS de Nmap | Registros y relaciones entre nombres e IPs |
| Web | curl, WhatWeb | Respuestas, cabeceras y tecnologías observadas |
| Contenido web | ffuf | Rutas y hosts virtuales; listas y límites seleccionados por el usuario |
| Comprobaciones web | Nikto | Observaciones y posibles problemas que requieren revisión |
| SMB/RPC | smbclient, enum4linux-ng, NetExec | Recursos compartidos e información del sistema/dominio según acceso disponible |
| LDAP/AD | ldapsearch, NetExec | Objetos y metadatos accesibles con el contexto de autenticación elegido |
| Relaciones AD | Colector compatible y BloodHound CE | Artefactos de recolección y análisis en BloodHound |
| SNMP | snmpwalk | Metadatos obtenidos con la comunidad/credencial proporcionada |
| NFS | showmount | Exportaciones anunciadas |
| TLS | openssl | Certificados y metadatos de conexión |

BloodHound se integra como un flujo propio: comprobar versión/formato, importar o recolectar datos compatibles, conservar artefactos y abrir la instancia de BloodHound configurada. No se recrea su motor de grafos en el MVP. SharpHound requiere un entorno Windows adecuado; no se presupone que todos los colectores pueden ejecutarse en Kali. La opción de recolección desde Kali se definirá según compatibilidad con la versión elegida de BloodHound.

Nikto aparece como comprobación adicional elegida por el usuario, diferenciada de descubrimiento e inventario. Una versión detectada no se convierte automáticamente en una vulnerabilidad confirmada.

## Editor bidireccional de comandos

La pantalla de nueva ejecución contiene dos vistas del mismo borrador: formulario y comando de terminal. El usuario puede trabajar en cualquiera de ellas y cambiar de vista sin perder parámetros.

### Formulario a comando

- Cambiar cualquier campo actualiza inmediatamente el comando.
- Cada parámetro tiene un control según su tipo: interruptor, texto, número, selector, lista, ruta/archivo o editor de estructura.
- Los campos se agrupan por función y se pueden buscar por nombre, flag o descripción. Las opciones avanzadas siguen disponibles; los perfiles son atajos que rellenan campos.
- No marcar una opción significa omitirla, no escribir explícitamente su valor por defecto. Se diferencian valores omitidos, valores vacíos y valores proporcionados.
- Repeticiones, listas ordenadas y opciones dependientes del orden tienen controles que mantienen su semántica.
- Un cambio en un perfil se indica como configuración personalizada.

### Comando a formulario

- Al pegar o terminar de escribir un comando válido se reconoce la herramienta/subcomando y se completan los campos correspondientes.
- Las opciones presentes abren sus grupos en el formulario, incluidos los avanzados.
- Se reconocen alias documentados, argumentos posicionales, formas con valor separado o unido, opciones repetibles, valores entre comillas y el marcador `--`, según la gramática de cada herramienta. No se trata toda opción corta como un grupo de flags: por ejemplo, `-sV` de Nmap tiene significado propio.
- Se conserva el texto original y el orden de los tokens hasta que el usuario realiza una edición que requiera regenerarlos. No se normalizan duplicados ni se reordenan argumentos sin una regla específica que preserve su significado.
- Un comando incompleto mantiene el último formulario válido e indica qué falta. No se reemplaza la entrada mientras el usuario escribe ni se inicia ninguna ejecución por pegar texto.
- Una opción desconocida permanece visible con su valor y ubicación; se marca como pendiente de interpretar. Nunca se descarta para aparentar una importación correcta. El borrador puede conservarse, pero la ejecución requiere un adaptador que la soporte y valide.
- Los errores señalan el fragmento del comando y el campo relacionado, sin borrar el resto de la configuración.

### Ejemplo de comportamiento

Entrada:

```text
nmap -sV -p 22,80,443 --open 192.168.56.10
```

El formulario selecciona Nmap, objetivo `192.168.56.10`, detección de versiones activada, puertos `22,80,443` y filtro de puertos abiertos activado. Cambiar el campo de puertos a `80,443,8080` actualiza únicamente ese argumento en el comando. Volver a interpretar el comando produce los mismos valores y estados explícitos.

### Autocompletado contextual

Además de rellenar los campos al importar un comando, el editor sugiere flags, subcomandos y valores enumerados compatibles con la versión detectada. Puede sugerir objetivos del proyecto, interfaces y rutas disponibles en Kali. Las sugerencias de archivos remotos se consultan bajo demanda; las rutas de herramientas son rutas de Kali aunque la UI esté en Windows.

Las credenciales pegadas se reconocen como secretos y pasan a controles enmascarados/referencias temporales. El texto sensible no se persiste en el historial, logs ni exportaciones. La UI indica cuando una representación copiable está redactada y no puede ejecutarse tal cual; no sustituye silenciosamente un secreto real por texto literal.

### Sintaxis y alcance del editor

El comando describe la herramienta que se ejecutará en Kali, también cuando se pega desde Windows. El editor utiliza reglas de tokenización de argumentos de estilo POSIX; no interpreta PowerShell o CMD. Debe indicar esta convención junto al campo.

Pipelines, redirecciones, expansión de variables, sustitución de comandos y cadenas de múltiples órdenes no se convierten en campos de una herramienta. Se detectan cuando funcionan como sintaxis de shell y se explican, preservando el texto. Esos caracteres dentro de un argumento literal entre comillas siguen siendo datos. La configuración de conexión SSH se administra por separado del comando de enumeración. Un prefijo `sudo` se identifica como solicitud de privilegios y requiere una capacidad configurada; no se convierte en ejecución arbitraria de shell.

### Cobertura por herramienta y versión

Cada adaptador mantiene un esquema versionado de parámetros: nombres y alias, aridad, tipo, repetibilidad, posición, formato, opciones incompatibles, dependencia de privilegios, tratamiento de secretos y controles de UI. Ese esquema alimenta formulario, parser, autocompletado, serializador y validación del runner.

La ayuda de la herramienta y su documentación completa sirven para revisar la cobertura; analizar únicamente `--help` no garantiza todas las opciones. La UI muestra versión detectada, versión del adaptador y cobertura verificada. Una herramienta no se presenta como completamente cubierta mientras queden opciones documentadas sin controles.

Los parámetros extensibles, como argumentos de scripts o plugins, disponen de editores genéricos de pares clave/valor o estructuras y ayuda específica cuando se conozca su esquema. No se promete enumerar estáticamente las opciones de cualquier plugin externo futuro.

Agregar nuevos módulos por etapas no reduce la cobertura de los ya entregados. La primera entrega debe cubrir los parámetros documentados de Nmap para la versión declarada, aunque los perfiles iniciales destacados sean descubrimiento, puertos e identificación de servicios.

## Entregas

### Entrega 1: recorrido completo con Nmap

- Proyectos, objetivos y conexiones.
- Ejecutor local y por SSH.
- Detección de instalación de Nmap.
- Perfiles de descubrimiento, puertos TCP e identificación de servicios.
- Editor bidireccional con cobertura completa de parámetros Nmap para la versión compatible declarada, búsqueda y autocompletado.
- Gestión de ejecución en memoria, logs, cancelación y límites de ejecución.
- Interpretación de XML, inventario y conservación de archivos.
- Importación de resultados Nmap existentes.

### Entrega 2: enumeración por servicio

- DNS, HTTP/TLS, contenido web, SMB, LDAP, SNMP y NFS.
- Adaptadores para las herramientas de cada área.
- Perfiles con límites de concurrencia y frecuencia apropiados para cada herramienta.
- Credenciales referenciadas por ID, con valores fuera de logs y exportaciones.
- Normalización cuando exista un formato fiable; salida original visible en todos los casos.

### Entrega 3: AD y comprobaciones web

- Flujo de BloodHound y colectores compatibles.
- Nikto como módulo opcional.
- Comparación entre ejecuciones y exportación consolidada.

## Arquitectura propuesta

### Stack implementado en la primera entrega

- Full stack: TanStack Start + TypeScript para rutas, UI, funciones de servidor, esquemas de opciones, API interna y adaptadores de ejecución.
- Componentes de interfaz: shadcn/ui para todos los controles de la aplicación, con un único tema y tokens visuales. CodeMirror se integra como editor especializado de comandos, manteniendo el mismo estilo visual.
- Persistencia de la aplicación: `localStorage` del navegador. No se introduce una base de datos.
- Trabajos: gestor en memoria del proceso TanStack Start y sondeo de estado/log por funciones de servidor. Las ejecuciones activas pertenecen al proceso que arrancó la app.
- SSH: cliente SSH de Node.js multiplataforma que fija la huella SHA-256 del host después de una confirmación explícita.
- Proceso remoto: runner Node.js pequeño en Kali, iniciado por una orden remota fija; recibe JSON estructurado y ejecuta módulos registrados con argumentos separados.
- Proceso local: el mismo catálogo y esquema de parámetros ejecuta las herramientas instaladas en la máquina donde corre TanStack Start.
- Versiones: el proyecto fija dependencias en `package-lock.json`; Node.js 22 o superior es el entorno recomendado para el runner.

La documentación de shadcn/ui ofrece una instalación específica para TanStack Start, así que no es necesario añadir una capa de componentes distinta.

Las funciones de servidor construyen trabajos con un identificador de módulo y opciones tipadas. El runner Nmap valida de nuevo el trabajo y ejecuta procesos con listas de argumentos, sin interpolar entradas del usuario en comandos de shell. El comando mostrado en la UI se genera desde esos mismos argumentos y oculta secretos. Los módulos de Nikto y BloodHound siguen pendientes.

El editor convierte texto y controles a una representación común de argumentos que preserva orden y repeticiones. El trabajo registra la versión del esquema y su configuración sin secretos; el runner rechaza incompatibilidades de esquema. Las opciones que modifican archivos de salida se respetan o se presentan como un conflicto explícito con la captura de artefactos. No se agregan o reemplazan flags silenciosamente para facilitar la interpretación de resultados: si el comando no genera un formato estructurado compatible, se conserva la salida original y se informa esa limitación.

Para SSH se usa una orden fija que inicia el runner; los trabajos viajan por entrada estándar como JSON. Los valores del formulario no se concatenan a la orden SSH. El cliente compara la huella SHA-256 del host con la guardada localmente. En el primer contacto la interfaz muestra la huella y exige que el usuario la compare con una fuente confiable antes de aceptarla. Un cambio posterior bloquea la conexión y pide volver a verificarla.

## Conexión SSH

Datos: nombre de conexión, host, puerto, usuario, ruta de clave privada y ruta del runner. La ruta de la clave pertenece a la máquina donde se ejecuta la app, Windows o Kali. Se prioriza autenticación por clave; el material de clave nunca se escribe en `localStorage`.

El diagnóstico comprueba autenticación, versión de Node.js, runner, herramientas y permisos. Las herramientas ausentes se muestran como no disponibles. Instalar herramientas o cambiar privilegios es una operación separada del diagnóstico.

El gestor en memoria mantiene el ID, estado y flujo de cada proceso mientras la app está activa. Cerrar el panel de logs no cancela la ejecución. Si se reinicia el proceso servidor, cualquier trabajo activo se marca como interrumpido al volver a abrir la app; no se promete recuperación de trabajos activos tras un reinicio.

Cancelar un trabajo significa detener su grupo de procesos en Kali y confirmar el resultado. Si SSH se interrumpe durante una cancelación, se registra como cancelación pendiente o estado desconocido y se reconcilia al reconectar; no se informa éxito sin evidencia.

Los resultados normalizados y las notas se guardan en el `localStorage` del navegador. La salida de terminal se conserva como texto mientras quepa dentro del límite de almacenamiento del navegador. Los reportes grandes y archivos originales se ofrecen como descargas al usuario; la app no los archiva en un servidor. Se puede exportar/importar una copia de proyectos y resultados en JSON para moverlos entre Windows y Kali.

Las conexiones, interfaces, rutas y listas de archivos pertenecen a la máquina que ejecuta los procesos. Las credenciales secretas no se guardan en `localStorage`; la app solicita su uso al ejecutar o se refiere a una clave SSH administrada fuera de la app. Las capacidades que requieren privilegios se detectan y documentan; no se asume sudo ilimitado ni se solicita una contraseña por un terminal oculto.

La retención en el runner se limita a datos operativos temporales durante la vida del trabajo. No se utiliza almacenamiento remoto como archivo permanente de la aplicación.

## Datos guardados en el navegador

- Project: nombre, alcance, exclusiones y notas.
- Connection: tipo, configuración SSH y referencias de autenticación.
- Target: dirección/nombre/URL introducido y proyecto.
- Asset: host descubierto, direcciones y nombres observados.
- Service: host, puerto, protocolo, estado, producto y versión observados.
- Job: proyecto, conexión, módulo, parámetros depurados, estado final y fechas.
- Observation: dato observado, evidencia, origen y momento de recolección.
- Artifact: referencia a un archivo descargado por el usuario, su tipo, nombre, hash y ejecución de origen.
- CredentialReference: referencia a una clave/credencial disponible en la máquina ejecutora; nunca su valor en `localStorage` o exportaciones.

Estos registros viven en `localStorage` y son específicos del origen y perfil del navegador. Kali y Windows tendrán almacenes distintos aunque abran la misma aplicación; la exportación/importación JSON permite trasladar el proyecto. El usuario puede borrar todos los datos desde Ajustes.

Cada escritura verifica cuota y espacio disponible. El panel muestra uso estimado y avisa antes de importar o guardar datos que se acerquen al límite. Los datos no se truncan en silencio: se propone exportar o quitar salidas crudas antiguas. Resultados normalizados, notas, objetivos y configuración tienen prioridad sobre el log completo. No se prometen copias automáticas ni sincronización entre dispositivos.

Las observaciones conservan su origen. Resultados contradictorios entre ejecuciones no se sobrescriben silenciosamente.

## Estados y límites

Estados: en cola, iniciando, ejecutando, completado, fallido, cancelación solicitada, cancelado y desconocido. Un timeout registra fallo por tiempo excedido y confirma la terminación remota cuando sea posible.

Cada trabajo configura timeout y concurrencia. Los módulos aplican el alcance y las exclusiones del proyecto; redirects, objetivos derivados y expansión de nombres requieren validación antes de ejecutar nuevas tareas. Descubrimiento de hosts no implica exploración automática de redes adicionales.

## Criterios de aceptación de la primera entrega

1. La aplicación inicia en Kali o Windows y escucha solo en localhost.
2. Windows ejecuta Nmap en Kali por SSH sin necesitar Nmap local.
3. Se comprueba y fija la huella SSH después de que el usuario la confirme; un cambio posterior bloquea la conexión.
4. Se muestra el comando sin credenciales y el log durante la ejecución.
5. Un XML de Nmap produce hosts y servicios con enlaces a evidencia.
6. Se pueden descargar salidas originales aunque no se puedan interpretar.
7. Cancelación, timeout y pérdida de conexión producen estados verificables.
8. Se rechazan objetivos fuera del alcance y entradas que intenten alterar la ejecución.
9. Recargar la página conserva datos del proyecto en el mismo navegador; cambiar de equipo/origen requiere exportar e importar JSON.
10. Si el navegador rechaza una escritura por cuota, la interfaz lo muestra y permite exportar o quitar datos; ningún resultado se descarta silenciosamente.
11. Cada opción documentada de la versión Nmap declarada tiene un control accesible y una correspondencia verificada en el esquema.
12. Formulario → comando → formulario conserva valores, omisiones, repeticiones y significado. Comando → formulario → comando mantiene equivalencia de argumentos; no se exige conservar espacios o estilo de comillas cuando se edita.
13. Se verifican opciones con argumentos separados/unidos, valores con espacios, argumentos posicionales, listas, rutas, opciones repetidas y opciones con sintaxis propia.
14. Opciones desconocidas, comillas incompletas y sintaxis de shell producen diagnósticos sin descartar entrada ni ejecutar texto automáticamente.
15. Editar comando y formulario rápidamente no causa bucles de actualización, pérdida de foco ni sobrescritura de un borrador incompleto.
16. Windows y Kali producen la misma lista de argumentos para un mismo borrador; archivos e interfaces se resuelven en el ejecutor seleccionado.
17. Todos los controles de producto proceden de shadcn/ui o son extensiones especializadas integradas en su tema.

## Referencias

- Nmap XML: https://nmap.org/book/output-formats-xml-output.html
- Nmap opciones y manual completo: https://nmap.org/book/man-briefoptions.html y https://nmap.org/book/man.html
- enum4linux-ng: https://www.kali.org/tools/enum4linux-ng/
- NetExec enumeración: https://www.netexec.wiki/smb-protocol/enumeration
- ffuf: https://github.com/ffuf/ffuf
- Nikto: https://cirt.net/nikto2-docs/usage.html
- BloodHound: https://bloodhound.specterops.io/
- TanStack Start overview: https://tanstack.com/start/latest/docs/framework/react/overview
- CodeMirror autocompletado: https://codemirror.net/examples/autocompletion/
- shadcn/ui para TanStack Start: https://ui.shadcn.com/docs/installation/tanstack
- `localStorage`: https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage

## Decisiones aún abiertas

- Marca y diseño visual.
- Primera entrega: aplicación local para un usuario; instancia del servidor accesible solo desde localhost.
- Formato de comandos: un ejecutable integrado y sus argumentos, sin pipelines ni sintaxis de shell.
- BloodHound: versión/instancia y colector compatible. Recomendación: definir recolección en una entrega aparte, con importación compatible en el primer flujo.
- Secretos: claves SSH administradas por el sistema y credenciales efímeras; no guardar contraseñas o claves privadas en `localStorage`.
- Retención: datos compactos en `localStorage` hasta que el usuario los borre; salidas grandes como descargas.
- Perfiles de Nmap: seleccionar los principales al implementar su esquema completo de parámetros.
- Multiusuario o acceso por red, si hace falta después.

