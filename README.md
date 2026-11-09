# security-service

Servicio de identidad independiente con Spring Boot 3.5.16, Java 25, Spring Cloud 2025.0.3, MySQL propio y Flyway. Mantiene usuarios, roles y vínculos UUID; no consulta bases de shipment ni courier.

## Arranque y esquema

Crear una base MySQL exclusiva, por ejemplo `security_db`. Definir `DB_URL`, `DB_USERNAME`, `DB_PASSWORD`; `SERVER_PORT` es opcional (8083). Ejecutar `./mvnw spring-boot:run` o abrir pom.xml con JDK 25. Flyway crea users y user_roles; Hibernate valida, no genera el esquema. No usar cuentas root ni registrar secretos en Git.

Los perfiles `dev` (predeterminado) y `prod` requieren Config Server mediante `CONFIG_SERVER_URL` (por defecto http://localhost:8888). Montar la clave RSA privada PKCS#8 en `JWT_PRIVATE_KEY_LOCATION=file:/ruta/private.pem`. La pública X.509 es opcional y se deriva de la privada si se omite. Solo `test` genera claves efímeras sin configuración; material configurado ilegible, inválido o que no coincide detiene el arranque.

ADMIN inicial está deshabilitado por defecto. Para aprovisionarlo, definir explícitamente `SECURITY_ADMIN_ENABLED=true`, `SECURITY_ADMIN_USERNAME`, `SECURITY_ADMIN_EMAIL` y una `SECURITY_ADMIN_PASSWORD` propia. Se rechazan contraseñas vacías o `admin123` antes de guardar el usuario.

User tiene UUID, email normalizado y único, hash BCrypt, roles ADMIN/CLIENTE/REPARTIDOR, habilitación y versión optimista. Las respuestas omiten el hash. No hay usuarios ni contraseñas iniciales incorporados.

Se implementan login, registro, JWT, perfil y administración; cada ruta exige el rol correspondiente y cualquier ruta nueva se deniega por defecto. OpenAPI está disponible en `/v3/api-docs` y `/swagger-ui/index.html`.

`JWT_ISSUER`, `JWT_KEY_ID`, `JWT_AUDIENCES` (destinatarios separados por coma) y `JWT_TTL` (duración ISO 8601) configuran los tokens. También se aceptan las propiedades planas de Config Repo para issuer, key-id, ubicaciones y token-ttl. `JWT_EXPIRATION_MS` positivo precede a `JWT_TTL`; después se usa `JWT_TTL_SECONDS`. TTL permitido: 1 a 86400 segundos. El recurso security exige que `aud` incluya `security-service`; los consumidores validan su propia audiencia.

## Endpoints implementados

- **`POST /api/v1/auth/register`**: Registro público exclusivamente `CLIENTE` con BCrypt. Payload inválido o escalación de privilegios/vínculos ajenos devuelve 400; duplicado, 409. Una operación administrativa sin el rol requerido devuelve 403.
- **`POST /api/v1/auth/login`**: Emite JWT RS256 con credenciales válidas; credenciales inválidas devuelven 401 sin distinguir si existe la cuenta.
- **`GET /api/v1/auth/me`**: Perfil del sujeto autenticado, sin hash ni claves.
- **`GET /api/v1/auth/jwks`** y **`GET /api/v1/auth/public-key`**: Material público de verificación; nunca la clave privada.
- **`POST /api/v1/users`**: Alta administrativa de usuarios privilegiados o con vínculos de dominio preasignados (exclusivo `ADMIN`).
- **`GET /api/v1/users/{id}`**: Consulta administrativa de perfil de usuario (exclusivo `ADMIN`).
- **`PUT /api/v1/users/{id}/roles`**: Actualización de roles de un usuario (exclusivo `ADMIN`).
- **`PUT /api/v1/users/{id}/customer-link`**: Vinculación confiable y única de `customerId` (exclusivo `ADMIN`).
- **`PUT /api/v1/users/{id}/courier-link`**: Vinculación confiable y única de `courierId` (exclusivo `ADMIN`).
- **`GET /actuator/health`**: Estado de salud público y mínimo.

Documentación detallada de la entrega S2-12: [docs/sprint2/S2-12.md](docs/sprint2/S2-12.md).

## Verificación

`./mvnw clean verify` usa H2 aislado en modo MySQL. El workflow bootstrap repite la suite con MySQL 8.4 y Flyway. Para repetir con una base descartable propia: TEST_DB_URL, TEST_DB_USERNAME y TEST_DB_PASSWORD. Nunca apuntar tests a datos reales.

CI también ejecuta Javadoc y construye la imagen. El smoke de la imagen usa MySQL, Config simulado, RSA montada y credenciales descartables; comprueba login, perfil, configuración remota y rechazos 401/403. No publica imágenes ni acredita la integración de los cuatro servicios reales.

[Revisión de las entregas de Gonzalo](docs/sprint2/REVISION-GONZALO.md).

[Contratos](https://github.com/Logitrack-Sa/shipment-service/blob/main/docs/sprint2/CONTRATOS.md) · [Tablero](https://github.com/orgs/Logitrack-Sa/projects/2). El revisor IA complementa las pruebas y la revisión humana.

## Registro en Eureka - Sprint 3 (#78)

Usar `SPRING_PROFILES_ACTIVE=prod,sprint3` y `CONFIG_SERVER_URL` para obtener
las propiedades centralizadas. En Compose, `EUREKA_SERVER_URL=http://eureka-server:8065/eureka/`
y `SERVICE_HOST=security-service` anuncian un nombre alcanzable desde el Gateway.
El cliente se registra como `SECURITY-SERVICE`. El perfil test desactiva
el descubrimiento para que las suites aisladas no dependan de infraestructura.
Sin el perfil sprint3, `EUREKA_CLIENT_ENABLED=false` conserva el arranque del Sprint 2.
La prueba distribuida debe comprobar registro UP, puerto anunciado y renovacion.

## Verificación de correo y Redis — Sprint 4 (#101, #102)

El registro público crea una cuenta deshabilitada, `emailVerified=false` y un token
UUID v4 válido durante 24 horas. El envío Gmail SMTP se despacha con `@Async`
únicamente después del commit. Configurar `GMAIL_SMTP_USERNAME`,
`GMAIL_SMTP_APP_PASSWORD` y, opcionalmente, `FRONTEND_URL` (por defecto
`http://localhost:3000`). No guardar credenciales en Git.

- `POST /api/v1/auth/verify-email?token=...`: activa la cuenta, verifica el correo y
  revoca sus tokens en una transacción. Devuelve `200` con `verified=true`.
  Un token vencido devuelve `400 VERIFICATION_TOKEN_EXPIRED`; uno inexistente,
  revocado o usado devuelve `404 INVALID_VERIFICATION_TOKEN`, ambos como
  `application/problem+json` con `status`, `detail`, `instance` y `code`.
- `POST /api/v1/auth/resend-verification`, cuerpo `{"email":"cliente@example.com"}`:
  revoca los enlaces anteriores, genera uno nuevo y despacha su correo después del
  commit. Devuelve `200` con `sent=true` y un mensaje condicional uniforme, incluso
  si la cuenta no existe o ya está verificada; no confirma entrega SMTP.
- Confirmación y reenvío bloquean la misma fila de usuario para serializar cambios
  concurrentes y evitar consumir dos veces un token o dejar dos reenvíos activos.

`GET /api/v1/auth/me` usa Cache-Aside en Redis, caché `user_profiles`, TTL de 15
minutos y valores JSON de `UserResponse` sin contraseñas. La clave lógica es
`user::username::<sub>`: el nombre del principal de Spring Security es el UUID
inmutable del JWT, no el campo opcional `User.username`. Así se conserva el
contrato de los JWT existentes sin mezclar perfiles ni hacer consultas SQL en un
acierto de caché. Las claves físicas llevan el prefijo `user_profiles::`.
Verificar correo, cambiar roles o vincular cliente/repartidor invalida el perfil
solamente después del commit; un rollback conserva la entrada anterior.

Configurar `SPRING_DATA_REDIS_HOST` y `SPRING_DATA_REDIS_PORT` (o `REDIS_HOST` y
`REDIS_PORT` sin Config Server), y `REDIS_PASSWORD` si corresponde. El fallo de
Redis se propaga al acceso al perfil; el despliegue debe tener Redis disponible.
La invalidación cambia los datos de `/me`, no los roles de JWT ya emitidos.

Pruebas: `./mvnw verify` ejecuta el flujo HTTP con H2 y correo simulado. Para
incluir TTL, serialización, aciertos e invalidación transaccional contra Redis
real, iniciar una instancia **descartable** y ejecutar
`TEST_REDIS_PORT=16379 ./mvnw verify`. La suite limpia `user_profiles`; no apuntarla
a un Redis con datos reales. CI ejecuta estas pruebas con Redis tanto sobre H2
como sobre MySQL. El envío y la recepción reales en Gmail quedan como validación
manual separada.

En equipos con memoria o CPU limitadas, evitar suites completas y contenedores
locales. Para comprobar solamente la compilación de fuentes y pruebas:
`JAVA_TOOL_OPTIONS="-Xmx256m -XX:ActiveProcessorCount=1" ./mvnw -DskipTests test-compile`.
La integración con Redis/MySQL queda a cargo de GitHub Actions.

### Alta automática de clientes

Después de verificar el correo, el primer login de una cuenta CLIENTE sin vínculo
aprovisiona su perfil en shipment-service. Security firma una identidad de 60 segundos,
con audiencia shipment-service y propósito customer-provision; no acepta customerId del
registro público. Shipment usa el UUID de usuario como propietario único y devuelve el
mismo cliente ante reintentos. Una coincidencia de email no permite apropiarse de otro
perfil. El JWT de sesión final incluye el customerId persistido.

Si Shipment no está disponible, el login devuelve 503 CUSTOMER_PROFILE_UNAVAILABLE;
al reintentar se recupera el perfil ya creado, sin duplicarlo. Las cuentas ADMIN y
REPARTIDOR conservan sus flujos. No se registra automáticamente un repartidor.
Security descubre shipment-service mediante Eureka. Su URL lógica se configura con
logitrack.customer-provisioning.url (predeterminado http://shipment-service).
El endpoint POST /api/v1/customers/provision requiere identidad firmada de propósito
específico; no se expone al público a través del Gateway.
