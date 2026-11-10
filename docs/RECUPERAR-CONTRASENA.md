# Recuperación de contraseña

Desde el login, **¿Olvidaste tu contraseña?** abre `/forgot-password`. Se solicita
el correo registrado. Una cuenta activa y verificada recibe un enlace a
`/reset-password#token=...`; también sirve para ADMIN y REPARTIDOR.
Los correos `example.test` de las cuentas de prueba no reciben correo externo.

- `POST /api/v1/auth/forgot-password` recibe `{ "email": "persona@example.com" }`.
  Devuelve siempre HTTP 202 y un mensaje uniforme. El trabajo se procesa de forma
  asíncrona; no se entrega el token en la respuesta. Máximo 30 solicitudes/minuto
  por instancia y un correo por cuenta cada 60 segundos.
- `POST /api/v1/auth/reset-password` recibe `{ "token": "...", "password": "..." }`.
  Devuelve HTTP 204. Token inválido, vencido o utilizado: HTTP 400. Máximo 60
  intentos/minuto por instancia. No se emite sesión automáticamente.
- Token aleatorio de 256 bits, 15 minutos, guardado únicamente como SHA-256.
  Una fila por cuenta evita acumulación; un nuevo enlace reemplaza al anterior.
  Bloqueos de cuenta y token impiden consumos concurrentes, también con MySQL
  REPEATABLE READ. La contraseña BCrypt y el consumo se confirman juntos.
- La contraseña admite entre 8 y 72 caracteres y como máximo 72 bytes UTF-8,
  por el límite de BCrypt. Roles, vínculos y estado de la cuenta se conservan.
- `FRONTEND_URL` define el origen público confiable, incluido `/logitrack` cuando
  corresponde. No se utiliza el Host enviado por el solicitante. SMTP reutiliza
  la configuración existente. En producción debe ser una URL HTTPS.
  Los fallos de entrega SMTP se reintentan una vez tras un segundo, sin bloquear
  la respuesta HTTP ni generar un token diferente. Un fallo definitivo queda en métricas.
- El token viaja en el fragmento, que no se envía en solicitudes HTTP ni Referer.
  La página declara `no-referrer` y no se indexa. Las respuestas usan `no-store`.
- El arranque del ADMIN conserva la contraseña persistida; cambiar la variable
  de bootstrap ya no reemplaza la contraseña de una cuenta existente.

La interfaz cierra la sesión del navegador donde se completa la recuperación.
Los JWT ya emitidos en otros dispositivos mantienen su vencimiento habitual;
esta entrega no agrega una lista de revocación distribuida entre microservicios.

Pruebas: cambio e inicio de sesión en los tres roles, rechazo de clave anterior,
vencimiento, reenvío, concurrencia, rollback, validación, límites y entrega SMTP
simulada. Referencia: [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).
