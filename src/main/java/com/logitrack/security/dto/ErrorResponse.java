package com.logitrack.security.dto;

import java.time.Instant;

/**
 * Estructura estándar para respuestas de error de la API REST.
 *
 * @param timestamp marca temporal en que se originó el error.
 * @param status código numérico de estado HTTP.
 * @param error descripción corta del estado HTTP.
 * @param code código funcional de error (ej. VALIDATION_ERROR, PRIVILEGE_ESCALATION, DUPLICATE_RESOURCE).
 * @param message mensaje explicativo seguro sin filtración de datos sensibles.
 * @param path ruta del recurso HTTP solicitado.
 */
public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String code,
        String message,
        String path
) { }
