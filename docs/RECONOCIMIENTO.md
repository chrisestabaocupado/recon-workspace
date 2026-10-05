# Reconocimiento pasivo

La ruta `/reconocimiento` integra recopilación, revisión de activos y evidencia por proyecto. Usa shadcn/ui, tema oscuro y el mismo localStorage, sin base de datos.

## Fuentes

- **crt.sh:** certificados públicos, consulta de nombre exacto o subdominios, timeout y deduplicación SAN. Omite comodines; no inventa hosts concretos a partir de ellos. Los certificados pueden ser históricos y los resultados parciales.
- **RDAP:** dominio registrado, fechas, estado, identificador del registrador y servidores DNS. El servidor elige un endpoint HTTPS del [directorio de IANA](https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml). No sigue redirecciones ni enlaces recibidos. Omite contactos personales y el JSON crudo.
- **Manual:** IP, CIDR, nombres exactos, observaciones sin activos, URL, fecha y contexto. También permite pegar JSON de crt.sh/RDAP y marca que su procedencia y fecha fueron declaradas por el operador.

Las consultas públicas requieren dominio público incluido explícitamente, plan aprobado, permiso **Reconocimiento pasivo en fuentes públicas**, ventana activa y timeout que quepa en ella. Se valida en cliente y servidor. Añadir el permiso invalida la aprobación anterior; los planes antiguos lo cargan deshabilitado.

Las peticiones HTTPS y la resolución de sus fuentes salen de Kali por SSH mediante la configuración global del navbar. Antes de consultar se exige una verificación vigente, vinculada a los campos y la huella del servidor; no se usa fetch local como alternativa. El timeout incluye conexión SSH y consultas a las fuentes. La fuente externa recibe el dominio consultado. No hay sondeos de los activos encontrados ni consultas DNS activas. Si el acuerdo prohíbe compartir el dominio, usar evidencia manual.

## Campos y comando

Fuente, dominio, subdominios y timeout se sincronizan con el comando curl equivalente. El parser acepta curl/curl.exe, --fail, --silent, --show-error, --location para RDAP, --max-time y sus alias cubiertos por las pruebas. Si no hay timeout se aplica el del adaptador: 25 segundos. Opciones desconocidas, shell y URLs ajenas bloquean el botón; no se ejecuta el texto en shell.

El comando equivalente se copia a la terminal de Kali. El parser conserva compatibilidad con curl.exe para comandos antiguos; la app siempre consulta desde Kali. El equivalente RDAP usa [rdap.org](https://about.rdap.org/); la app consulta el endpoint de IANA. Son recorridos diferentes: el CLI puede seguir redirecciones que la app bloquea. No hay cobertura general de todos los parámetros curl.

## Flujo y trazabilidad

1. Seleccionar proyecto, revisar el plan y habilitar/aprobar el permiso pasivo si se harán consultas públicas.
2. Comprobar Kali por SSH desde el navbar antes de consultar una fuente. Guardar evidencia manual no exige una conexión. En redes internas, usar documentación e inventarios del propietario.
3. Revisar candidatos, documentar propiedad, confianza y terceros, y marcar Revisado o Descartado.
4. Enviar a Enumeración solo activos revisados, incluidos y no excluidos, con plan aprobado y vigente. Se evitan duplicados, se enlazan las fuentes en la nota del objetivo y no se inicia un escaneo.
5. Incorporar subdominios fuera del plan mediante un nuevo acuerdo/aprobación en Alcance. Descubrirlos no amplía los permisos.
6. Descargar Markdown o exportar JSON de proyectos. Importar ese JSON desde Enumeración conserva reconocimiento.

La evidencia guarda fuente, consulta, URL, fecha, revisión del plan e identidad del ejecutor SSH (host, puerto, usuario y huella), sin secretos. La evidencia manual y los registros antiguos pueden carecer de ejecutor. Una revisión asociada a evidencia manual documenta el contexto de registro; no prueba que autorizase una recopilación histórica. Los candidatos conservan notas, estado y varias fuentes. Recopilar otra vez no borra una revisión previa del operador.

Eliminar evidencia exige confirmación en la UI y elimina candidatos sin otras fuentes. Los objetivos ya enviados a Enumeración permanecen; su nota puede referirse a una evidencia eliminada. Exportar antes de borrar si se necesita trazabilidad íntegra. Retención y borrado de archivos descargados son manuales.

## Límites

100 evidencias y 2500 candidatos por proyecto, dentro de los 5 MB globales del workspace. Cada consulta conserva hasta 500 candidatos; crt.sh avisa de resultados parciales. Una consulta simultánea y seis por minuto en el servidor, sin reintentos automáticos. Timeout de 5–60 segundos y respuestas de hasta 3 MB. Errores HTTP, TLS, JSON, cuota y redirección aparecen en la UI.

La navegación interna espera a que termine la consulta para guardar la respuesta. Recargar/cerrar durante una petición puede perder la respuesta: hay aviso de salida y la operación pendiente se recupera como resultado sin confirmar, sin inventar evidencia ni afirmar que Kali falló. Los borradores manuales sin guardar se descartan al salir.

Pruebas: parsers, roundtrip curl, permisos, compatibilidad, deduplicación, límites, redacción, importación/exportación, promoción y respuestas HTTP simuladas. No contactan los dominios sintéticos. En el navegador (origen de prueba 127.0.0.1:3100) se comprobaron carga manual, revisión, persistencia, exclusiones y descarga Markdown. La disponibilidad real de crt.sh y cada registro RDAP debe probarse con un dominio autorizado.

Pendientes: adaptadores activos DNS/HTTP en Kali por SSH, tecnologías observadas, theHarvester/Subfinder y fuentes con API. Las comprobaciones no sustituyen la autorización escrita ni verifican propiedad o permisos de terceros.

Referencia crt.sh: [parámetro output=json en el grupo del proyecto](https://groups.google.com/g/crtsh/c/sCpRljHP4dw).


## Incidencias de reconocimiento y enumeración

Ambas páginas muestran **Incidencias e intentos fallidos**, con fecha, etapa, mensaje, fuente/objetivo, revisión del plan y, cuando existe, ID de ejecución y comando depurado. Se registran consultas fallidas de crt.sh/RDAP/DNS/TLS, errores parciales DNS/TLS, verificación SSH y herramientas, importaciones, revisión/promoción/eliminación de evidencia, inicio y estados fallidos de Nmap, seguimiento, cancelación no confirmada y recuperación/interpretación del XML. Una cancelación solicitada y confirmada no se clasifica como fallo.

**Copiar registro** y **Descargar registro** permiten compartir las incidencias. En Reconocimiento, **Copiar todo**, **Copiar evidencias** e **Informe Markdown** incluyen las incidencias del proyecto, incluso sin evidencia exitosa. **Exportar proyectos** conserva las incidencias de ambas fases y las operaciones pendientes; importar archivos antiguos sigue funcionando.

Cada reintento explícito recibe su propio ID. Las consultas repetidas de seguimiento de una misma ejecución se agrupan con primera/última fecha, contador y último error. Los fallos quedan vinculados al proyecto original aunque cambie la selección; si el proyecto desapareció se conservan en el registro sin proyecto. El registro no crea activos, no autoriza pruebas y no convierte un fallo de fuente en evidencia de vulnerabilidad. ENODATA/ENOTFOUND no se clasifican como errores de transporte DNS; EBADRESP/ETIMEOUT sí producen incidencias parciales.

La retención es local: últimas 300 incidencias por proyecto y otras 300 sin proyecto, dentro del límite global de 5 MB. Exporta para conservar registros anteriores. Si el navegador no permite guardar, se muestra el error y el registro queda en memoria hasta poder exportar o guardar. No se guardan frases de contraseña, tokens de verificación ni claves privadas en las incidencias. Los errores anteriores a esta adaptación no se reconstruyen automáticamente.

Validación: 70 pruebas automatizadas, TypeScript, lint y build; pruebas de interfaz con datos sintéticos comprobaron importaciones fallidas, recarga y copia, sin consultas ni escaneos de objetivos reales.

## Checklist por proyecto

Reconocimiento y Enumeración muestran **Checklist de pruebas** antes del registro de incidencias. Cada fila identifica prueba y objetivo; Nmap separa comandos distintos. El último intento determina el estado: Con datos, Sin datos, Falló, Parcial, Sin confirmar, Cancelada, Ejecutada, En curso o Pendiente. Un fallo posterior puede cambiar el estado aunque permanezca evidencia de una consulta anterior. Una consulta exitosa posterior muestra **Reintento resuelto**, conservando los errores previos en **Ver intentos**.

Con datos/Sin datos son resultados de recopilación; no equivalen a vulnerabilidad confirmada o ausencia de vulnerabilidades. Un DNS que responde A pero falla SOA queda Parcial. Un diagnóstico Nmap completado sin inventario queda Ejecutada; la cancelación voluntaria no queda como fallo. La evidencia manual y los JSON importados aparecen como Datos aportados, sin presentarlos como consultas ejecutadas por la app. La marca indica intento registrado, no éxito ni permiso para ejecutar. Las filas pendientes de reconocimiento se generan para los dominios exactos del plan: DNS, TLS, crt.sh y RDAP, sin ampliar a otros dominios ni consultar automáticamente.

Por defecto se muestra la revisión actual del plan. **Incluir revisiones anteriores** permite inspeccionar resultados anteriores y registros sin revisión; no se usan para dar por probada una revisión nueva. Los filtros separan completadas, fallos/parciales y pendientes. **Copiar checklist** y **Descargar checklist** incluyen estados e intentos de la revisión seleccionada; el filtro de estado afecta solo a la vista. El informe Markdown y Copiar todo/evidencias de Reconocimiento incluyen el checklist con todas las revisiones. Exportar JSON conserva el historial.

Se reconstruyen los resultados a partir de las evidencias y reportes que ya están guardados, y se conservan hasta 500 resultados nuevos por proyecto, dentro del límite global de 5 MB. Eliminar una evidencia no borra que la prueba se ejecutó, pero no restaura la evidencia eliminada. La retención de diez reportes Nmap compactos no borra los nuevos registros del checklist. Los intentos antiguos que nunca se guardaron no se reconstruyen.

Validación del checklist: 79 pruebas automatizadas, TypeScript, lint y build. La UI se comprobó con un proyecto sintético en puerto 3001, sin consultas de red: estados, reintento resuelto, filtros, recarga y copia/pegado Markdown.
