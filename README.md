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
