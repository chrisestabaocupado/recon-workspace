# Informes de reconocimiento y mapeo

La ruta `/informe` presenta un informe consolidado del proyecto seleccionado. No necesita conexión a Kali, un plan aprobado ni solicitudes de red para consultar o exportar los datos ya guardados. No sustituye una autorización ni evalúa vulnerabilidades.

## Contenido

- Resumen y cantidades de activos no descartados, hosts observados, puertos cuyo último estado es exactamente `open` y evidencias.
- Plan actual, autorización registrada, inclusiones, exclusiones, ventana, técnicas, límites y tratamiento de la evidencia.
- Objetivos y activos descubiertos, incluidos los descartados, su revisión manual y evidencias vinculadas. Revisado no significa autorizado.
- Mapa tabular de hosts y puertos/servicios, con producto, versión y CPE cuando existen. No se inventa una topología de red.
- Evidencias de reconocimiento, hechos, fuentes, advertencias, notas, fechas, revisiones y ejecutor SSH registrado.
- Checklist de la revisión actual, con actividades pendientes o en curso, historial de ejecuciones y sus errores e incidencias del proyecto. Se excluyen incidencias globales sin proyecto.
- Limitaciones y siguientes pasos de recopilación y verificación del inventario.

## Inventario y trazabilidad

Se combinan las últimas observaciones guardadas por dirección y por pareja protocolo/puerto, según su fecha. Un escaneo que no menciona un puerto no lo marca como cerrado. Una observación explícita posterior sí reemplaza su estado anterior. Los puertos conservan su propia fecha, ID de ejecución, resultado y revisión de origen, aunque el plan actual sea otro. Los escaneos fallidos o incompletos pueden aportar observaciones parciales y se muestran como tales.

El historial conserva hasta diez reportes compactos por proyecto. Por tanto, el mapa no garantiza todos los activos observados alguna vez ni disponibilidad actual. Un servicio, una versión, un CPE o un certificado no son hallazgos de vulnerabilidad. Si hay operaciones activas, la pantalla avisa y el informe solo incluye resultados guardados y actividades todavía sin confirmar.

## Exportación

1. Selecciona el proyecto y revisa la vista previa.
2. **Markdown** descarga un `.md` UTF-8; **Copiar** copia el mismo contenido documental. El texto libre se escapa para no interpretar HTML como contenido ejecutable.
3. **Imprimir / PDF** abre el diálogo del navegador. Elige **Guardar como PDF**. La impresión usa un documento aislado en A4 con fondo blanco, encabezados de tabla repetidos y sin menús, controles ni indicadores globales.
4. La vista, Markdown y PDF parten del mismo modelo de informe y fecha de generación. Se depuran patrones comunes de secretos y claves privadas, pero revisa manualmente los datos sensibles antes de compartir.

El informe se regenera a partir del proyecto; no mantiene versiones firmadas ni un archivo de entregas. Guarda cada archivo exportado si necesitas conservar una entrega específica. Usa la exportación JSON del workspace como respaldo editable y descarga los XML desde Enumeración antes de reiniciar el servidor.

## Compatibilidad con proyectos antiguos

Se mantienen los datos de alcance, reconocimiento y Nmap. El módulo de análisis y sus herramientas exclusivas ya no existen. La validación de lectura/importación elimina el campo antiguo `analysis`, los permisos `analysisTools` y las incidencias/operaciones pendientes de la fase retirada. No se reinicia el workspace ni se borran sus proyectos por contener estos campos antiguos. La siguiente persistencia o exportación JSON usa únicamente las fases vigentes.
