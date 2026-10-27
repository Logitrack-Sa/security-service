package com.logitrack.security.exception;

/**
 * Excepción lanzada cuando una petición intenta elevar privilegios o autoasignar identidades
 * en un flujo no permitido (ej. solicitar rol ADMIN/REPARTIDOR o customerId/courierId en registro público).
 */
public class PrivilegeEscalationException extends RuntimeException {

    /**
     * Construye una nueva excepción con el mensaje descriptivo especificado.
     *
     * @param message detalle del motivo de rechazo de elevación de privilegios.
     */
    public PrivilegeEscalationException(String message) {
        super(message);
    }
}
