package com.logitrack.security.controller;

import com.logitrack.security.dto.ErrorResponse;
import com.logitrack.security.exception.DuplicateResourceException;
import com.logitrack.security.exception.PrivilegeEscalationException;
import com.logitrack.security.exception.ResourceNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.time.Instant;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/**
 * Manejador centralizado de excepciones para la API REST de seguridad.
 *
 * <p>Mapea errores de validación, violaciones de integridad, escalación de privilegios
 * y recursos no encontrados a respuestas estandarizadas {@link ErrorResponse} con los
 * códigos HTTP correspondientes (400, 404, 409). Garantiza que nunca se expongan datos
 * sensibles, contraseñas ni hashes en las respuestas de error.</p>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Constructor público para el manejador global de excepciones.
     */
    public GlobalExceptionHandler() {
    }

    /**
     * Captura excepciones de recursos no encontrados (404).
     *
     * @param request petición HTTP en curso.
     * @return respuesta de error 404 NOT_FOUND.
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> missing(HttpServletRequest request) {
        return error(HttpStatus.NOT_FOUND, "RESOURCE_NOT_FOUND", "El recurso no existe", request);
    }

    /**
     * Captura intentos no autorizados de escalación de privilegios o vinculación ajena (400).
     *
     * @param request petición HTTP en curso.
     * @param ex excepción de escalación de privilegios.
     * @return respuesta de error 400 BAD_REQUEST con el motivo específico.
     */
    @ExceptionHandler(PrivilegeEscalationException.class)
    public ResponseEntity<ErrorResponse> privilegeEscalation(HttpServletRequest request, PrivilegeEscalationException ex) {
        return error(HttpStatus.BAD_REQUEST, "PRIVILEGE_ESCALATION", ex.getMessage(), request);
    }

    /**
     * Captura errores de validación de sintaxis o formato en el cuerpo de la petición (400).
     *
     * @param request petición HTTP en curso.
     * @return respuesta de error 400 BAD_REQUEST.
     */
    @ExceptionHandler({MethodArgumentNotValidException.class, ConstraintViolationException.class,
            HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<ErrorResponse> invalid(HttpServletRequest request) {
        return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", "Revisá los campos de la solicitud", request);
    }

    /**
     * Captura duplicidad de recursos controlada por la capa de negocio (409).
     *
     * @param request petición HTTP en curso.
     * @param ex excepción de recurso duplicado.
     * @return respuesta de error 409 CONFLICT con el mensaje explicativo.
     */
    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ErrorResponse> duplicate(HttpServletRequest request, DuplicateResourceException ex) {
        return error(HttpStatus.CONFLICT, "DUPLICATE_RESOURCE", ex.getMessage(), request);
    }

    /**
     * Captura violaciones de restricciones de unicidad o integridad en base de datos (409).
     *
     * @param request petición HTTP en curso.
     * @return respuesta de error 409 CONFLICT.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> conflict(HttpServletRequest request) {
        return error(HttpStatus.CONFLICT, "DATA_CONFLICT", "Los datos entran en conflicto con un registro existente", request);
    }

    private ResponseEntity<ErrorResponse> error(HttpStatus status, String code, String message, HttpServletRequest request) {
        return ResponseEntity.status(status).body(new ErrorResponse(Instant.now(), status.value(),
                status.getReasonPhrase(), code, message, request.getRequestURI()));
    }
}
