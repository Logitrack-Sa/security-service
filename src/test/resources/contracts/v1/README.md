# Contratos y Fixtures de Identidad (Sprint 2 - v1)

Este directorio contiene las especificaciones y fixtures de contrato estandarizados para la autenticación y autorización distribuida entre microservicios (`security-service`, `courier-service`, `shipment-service`).

## 1. Identidades Canónicas (`identities.json`)

Define los cinco sujetos fijados para pruebas aisladas de integración y verificación de aislamiento entre tenants/actores:

| Clave | `sub` (UUID) | Roles | Vínculo de Dominio | Descripción |
|---|---|---|---|---|
| `admin` | `00000000-0000-0000-0000-000000000001` | `["ADMIN"]` | N/A | Operador global del sistema, provisión y consultas totales. |
| `cliente-a` | `00000000-0000-0000-0000-000000000002` | `["CLIENTE"]` | `customerId: 10000000-0000-0000-0000-000000000001` | Cliente final A; solo opera sobre recursos con su propio `customerId`. |
| `cliente-b` | `00000000-0000-0000-0000-000000000003` | `["CLIENTE"]` | `customerId: 10000000-0000-0000-0000-000000000002` | Cliente final B; completamente aislado de cliente A. |
| `repartidor-a` | `00000000-0000-0000-0000-000000000004` | `["REPARTIDOR"]` | `courierId: 20000000-0000-0000-0000-000000000001` | Repartidor A; solo opera sobre envíos asignados a su `courierId`. |
| `repartidor-b` | `00000000-0000-0000-0000-000000000005` | `["REPARTIDOR"]` | `courierId: 20000000-0000-0000-0000-000000000002` | Repartidor B; completamente aislado de repartidor A. |

## 2. Reglas Criptográficas y Claims de JWT

1. **Algoritmo:** Exclusivamente `RS256` (RSA Signature with SHA-256). Se rechazan `HS256`, `none` y curvas elípticas no soportadas.
2. **Cabecera JOSE:** Requiere `kid` ("logitrack-main" o identificador activo) y `typ: JWT`.
3. **Claims estándar:**
   - `sub`: UUID del usuario autenticado (cadena canónica).
   - `iss`: Identificador URI del emisor confiable (`https://security-service`).
   - `aud`: Audiencia que incluye el servicio receptor (`security-service`, `courier-service`, `shipment-service`).
   - `iat`: Timestamp UTC de emisión.
   - `exp`: Timestamp UTC de expiración.
   - `roles`: Arreglo de cadenas JSON con los roles asignados (`["ADMIN"]`, `["CLIENTE"]`, `["REPARTIDOR"]`).
4. **Claims de dominio confiables:**
   - `customerId`: UUID del cliente asociado en base de datos.
   - `courierId`: UUID del repartidor asociado en base de datos.
   *Nota: Estos vínculos nunca son provistos ni aceptados desde el cuerpo del login o registro público.*

## 3. Verificación Descentralizada (Sin Dependencia HTTP)

Los servicios consumidores validan los tokens de forma 100% local:
- Verificación de firma criptográfica mediante la clave pública RSA (obtenida al arrancar o vía JWKS/archivo PEM).
- Validación de fecha de expiración (`exp`), emisor (`iss`), audiencia (`aud`) y algoritmo (`alg=RS256`).
- No se realiza ninguna solicitud HTTP saliente hacia `security-service` durante el ciclo de vida de una petición protegida.
