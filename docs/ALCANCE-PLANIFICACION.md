# Alcance y planificación

La ruta `/alcance` administra proyectos y sus reglas de compromiso. Mantiene shadcn/ui, tema oscuro y localStorage; no introduce una base de datos. La referencia de diseño es [NIST SP 800-115, sección 6 y apéndice B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf).

## Datos del compromiso

- Organización o propietario, objetivo y criterio de éxito, perspectiva interna/externa y responsable de las pruebas.
- Persona que autoriza y referencia de la autorización escrita, conservada fuera de la app.
- IP, CIDR IPv4/IPv6 o nombres DNS exactos incluidos; exclusiones con prioridad.
- Técnicas Nmap permitidas, puertos, direcciones por ejecución, paquetes/s y timeout.
- Permiso explícito de reconocimiento pasivo en fuentes públicas. Los planes antiguos lo cargan deshabilitado; cambiarlo exige otra aprobación. Consulta [Reconocimiento](RECONOCIMIENTO.md).
- Ventana de inicio/fin, origen y conectividad, contactos de coordinación e incidentes.
- Actividades prohibidas, condiciones de parada/reanudación, clasificación, destinatarios, retención y entregables de evidencia.

Los proyectos existentes conservan sus datos y requieren completar un plan. Su antiguo texto de alcance sirve de referencia; no equivale a aprobación.

## Flujo

1. Crear o seleccionar proyecto y completar las cuatro pestañas.
2. Guardar el borrador. Los cambios locales sin guardar se descartan al salir de la página; se avisa y se bloquea el selector de proyecto hasta guardar o descartar.
3. Revisar los datos pendientes. Registrar aprobación exige confirmar que existe autorización escrita para los activos, terceros pertinentes, técnicas y ventana; la app no obtiene ni firma esa autorización.
4. En Enumeración, elegir destinos dentro del plan. **Aplicar límites del plan al comando** muestra los flags efectivos; no se añaden silenciosamente al lanzar.
5. Usar un comando como `nmap -sT -sV -Pn -p 22,80,443 --max-rate 100 -oX - <IP_LAB>` y un timeout que quepa en la ventana. Ajustar servicios y límites al compromiso real.
6. Pausar bloquea nuevos trabajos y solicita cancelar el trabajo activo de ese proyecto en el navegador. Revisar su terminación en Enumeración. Cerrar conserva los registros; eliminar el proyecto requiere confirmación en la UI.
7. Exportar el plan en Markdown o los proyectos en JSON. Cada ejecución guarda la revisión usada. Al guardar cambios se invalida la aprobación anterior y se conserva la revisión con autorización previa, hasta diez revisiones históricas descargables.

## Comprobaciones automáticas

La misma política se comprueba en cliente y servidor: aprobación, campos requeridos, ventana, timeout, inclusión/exclusión, familia de IP, cantidad de direcciones, técnicas, puertos y tasa explícita `--max-rate`. Un rango parcialmente excluido se bloquea incluso si Nmap contiene exclusiones; usar destinos o rangos permitidos completos.

Los nombres deben figurar explícitamente en el alcance. Se resuelven exclusivamente desde Kali por SSH, con la familia elegida; se comprueban todas las direcciones devueltas y se fija la primera en el comando efectivo. Las exclusiones DNS también se resuelven para detectar alias que apuntan al mismo host. Fallos DNS o una IP excluida bloquean el inicio. Se admiten hasta 64 nombres entre objetivos y exclusiones por comprobación.

La duración incluye el establecimiento del trabajo. La ventana se revalida antes de enviar el inicio al runner; la cancelación y los estados de terminación siguen el gestor de ejecuciones.

NSE, `-A`, archivos de entrada, destinos aleatorios, reanudación, opciones desconocidas y otras opciones que pueden derivar destinos requieren validadores específicos y quedan bloqueados en este flujo. Los controles del catálogo siguen visibles. Diagnósticos aislados (`--version`, ayuda o interfaces) no necesitan un plan aprobado y no habilitan un escaneo.

## Límites operativos

La app registra la declaración del operador; no verifica firmas, propiedad de activos ni permisos contractuales de terceros. El plan procede del almacenamiento local y se envía al servidor de la aplicación personal: estas comprobaciones no constituyen un sistema de autorización multiusuario ni una frontera frente a un cliente que falsifique su plan.

La IP pública de origen, degradación de servicios, incidentes y reglas redactadas en texto requieren supervisión humana. Retención y borrado de evidencia exportada son manuales; no hay purga automática ni cifrado añadido a localStorage. Cambiar un plan no cambia el trabajo ya iniciado: pausar solicita su cancelación, pero otras pestañas o instancias deben supervisarse por separado.

Las comprobaciones de IP/DNS usan datos sintéticos en las pruebas. La conexión SSH y el recorrido con Kali real siguen pendientes de validación en el laboratorio autorizado.

