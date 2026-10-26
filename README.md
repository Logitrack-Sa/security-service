# security-service

Base independiente de Spring Boot 3.5.16 y Java 25 para la issue #1. Capas `entity`, `repository`, `service`, `dto`, `controller` (errores) y `config`; Maven Wrapper y Flyway. No depende de shipment ni courier.

## Arranque y esquema

Crear una base MySQL exclusiva, por ejemplo `security_db`. Definir `DB_URL`, `DB_USERNAME`, `DB_PASSWORD`; `SERVER_PORT` es opcional (8083). Ejecutar `./mvnw spring-boot:run` o abrir pom.xml con JDK 25. Flyway crea users y user_roles; Hibernate valida, no genera el esquema. No usar cuentas root ni registrar secretos en Git.

User tiene UUID, email normalizado y único, hash BCrypt, roles ADMIN/CLIENTE/REPARTIDOR, habilitación y versión optimista. Las respuestas omiten el hash. No hay usuarios ni contraseñas iniciales incorporados.

Solo GET /actuator/health es público y devuelve estado mínimo. El resto se deniega mientras se implementan autenticación y autorización en sus issues. Esta entrega no implementa login, registro público, JWT, provisión de ADMIN ni vinculación de identidades; tampoco activa Config Client o Docker de futuras tareas.

## Verificación

`./mvnw clean verify` usa H2 aislado en modo MySQL. El workflow bootstrap repite la suite con MySQL 8.4 y Flyway. Para repetir con una base descartable propia: TEST_DB_URL, TEST_DB_USERNAME y TEST_DB_PASSWORD. Nunca apuntar tests a datos reales.

[Contratos](https://github.com/Logitrack-Sa/shipment-service/blob/main/docs/sprint2/CONTRATOS.md) · [Tablero](https://github.com/orgs/Logitrack-Sa/projects/2). El revisor IA complementa las pruebas y la revisión humana.
