# Revisión de las entregas de Gonzalo

## Alcance

Integra en develop las ramas originales de las issues #2 a #8, conservando sus commits y la base de #1. Los PR originales son #13 a #19. La promoción a main y la entrega distribuida tienen su propia revisión.

## Correcciones

- La contraseña ADMIN ya no tiene valor incorporado y se valida antes de escribir datos.
- Solo test genera RSA efímera sin configuración; una clave configurada inválida o un par que no coincide siempre falla. Claves RSA mínimas de 2048 bits.
- Filtro HTTP y servicio JWT usan la misma validación RS256: issuer, audiencia del recurso, kid, sub UUID, roles conocidos, iat y exp obligatorios.
- Config Client usa el BOM compatible con Boot 3.5; dev/prod requieren Config Server. Se comprueban issuer y TTL desde el contrato plano de Config Repo.
- La imagen usa UID 10001 y bases fijadas por digest. CI construye y ejecuta la imagen con MySQL propio, RSA montada y Config simulado.

## Evidencia reproducible

- `./mvnw clean verify`: 106 pruebas, incluidas seis regresiones de JWT y siete de claves/bootstrap, más bootstrap remoto en dev/prod.
- CI: suite con MySQL, Javadoc e imagen; la ejecución enlazada en el PR identifica el commit verificado.
- `.github/scripts/smoke_auth.py`: salud, login inválido, login ADMIN, perfil, firma alterada, issuer/TTL remoto, registro CLIENTE y denegaciones administrativas.

No acredita imágenes publicadas, conexión con los servicios reales de otros repositorios ni la demo distribuida. Los apuntes S2 originales describen la entrega inicial; este documento y README describen las correcciones finales.
