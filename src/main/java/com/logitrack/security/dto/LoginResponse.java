package com.logitrack.security.dto;

/**
 * Respuesta exitosa de autenticación con el token de acceso emitido.
 *
 * <p>Sigue el contrato del Sprint 2 para la autenticación en el ecosistema LogiTrack:</p>
 * <ul>
 *   <li>{@code accessToken}: Cadena serializada del JWT firmado con RS256.</li>
 *   <li>{@code tokenType}: Esquema de autorización estándar ({@code Bearer}).</li>
 *   <li>{@code expiresIn}: Tiempo de expiración del token en segundos.</li>
 * </ul>
 *
 * @param accessToken token JWT firmado listo para utilizar en la cabecera {@code Authorization}.
 * @param tokenType tipo de token portador (típicamente {@code Bearer}).
 * @param expiresIn vigencia del token en segundos.
 */
public record LoginResponse(
        String accessToken,
        String tokenType,
        long expiresIn
) {
}
