# Terminal remota del navbar

El botón **Terminal**, junto a **Configurar Kali**, abre un shell interactivo dentro de la aplicación. Utiliza exactamente el host, puerto, usuario, clave y huella de la configuración SSH global; nunca abre una consola local en Windows ni utiliza un ejecutor alternativo.

## Uso

1. Configura Kali y comprueba SSH. En el primer contacto, compara y acepta su huella por un canal confiable.
2. Pulsa **Terminal**. Si no hay una verificación válida, el botón abre la configuración SSH.
3. Comprueba el destino `usuario@host:puerto` que aparece en el diálogo. Puedes escribir comandos, usar autocompletado con Tab, flechas, Ctrl+C y aplicaciones interactivas gracias al PTY remoto. El tamaño se ajusta al diálogo.
4. Usa **Cerrar terminal y desconectar** o **×** para terminar la sesión. Escape se reserva para el shell y no cierra el diálogo. Un clic fuera tampoco lo cierra accidentalmente.

**Limpiar vista** solo limpia el emulador; no detiene un comando. El botón **Ctrl+C** envía la interrupción al proceso en primer plano. No hay reconexión ni reenvío automático de comandos: si se pierde SSH, cierra el diálogo y abre una sesión nueva.

**Copiar todo**, junto a **Limpiar vista**, copia al portapapeles el texto de la pantalla y del historial conservado en el emulador (hasta 3000 líneas de historial), sin códigos ANSI y sin saltos artificiales por el ancho de la terminal. No recupera salida descartada o eliminada al limpiar la vista. El botón confirma **Copiado** o muestra un aviso si el navegador impide acceder al portapapeles.

## Alcance y seguridad

- Es una consola manual con los permisos del usuario SSH, no una ejecución gestionada de reconocimiento. Sus comandos **no se validan contra el plan aprobado**, no actualizan el inventario y no se incorporan a los informes. Úsala únicamente en sistemas y operaciones autorizados.
- La aplicación no guarda entradas ni salida en `localStorage`, historial de operaciones o reportes. No obstante, el shell remoto puede guardar su propio historial y mostrar credenciales en pantalla, como cualquier terminal SSH.
- Se verifica la configuración global al abrir y la huella se comprueba de nuevo al conectar. Una sesión ya abierta conserva su destino original aunque cambie la configuración o se renueve la verificación.
- Cada sesión tiene una capacidad secreta aleatoria en memoria, enviada solo en cuerpos POST. Las operaciones de entrada, salida, tamaño y cierre requieren esa capacidad. No se publican claves privadas ni se incluyen credenciales en URLs.
- El emulador se carga bajo demanda. La salida se consulta mientras el diálogo está abierto, con offsets para evitar duplicados; el servidor conserva como máximo 256 Ki caracteres por sesión. Si se pierde salida por exceso de volumen, la terminal lo indica. La entrada se envía en orden y nunca se reintenta automáticamente.
- Se permiten hasta cuatro sesiones por proceso del servidor. Si una pestaña desaparece o deja de comunicarse durante 60 segundos, se cierra la conexión y se descarta la salida; una pestaña suspendida por el navegador puede caducar. Reiniciar el servidor también pierde las sesiones.
- Cerrar SSH no garantiza detener procesos desacoplados (`nohup`, `tmux`, servicios, etc.). Comprueba su estado en Kali antes de repetir una operación.
- Mantén la aplicación vinculada a localhost, como indica el README. La terminal no añade un sistema de autenticación multiusuario; no expongas el servidor directamente a redes no confiables.

## Validación

`tests/terminal.test.mjs` comprueba verificación y huella, aislamiento de capacidades, límites de entrada/salida, offsets, expiración, PTY, UTF-8, teclas, redimensionado y cierre con transportes controlados. No abre conexiones de red. La aceptación final requiere comprobar la sesión contra la instancia Kali del operador.
