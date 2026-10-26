package com.logitrack.security.exception;

/**
 * Excepción lanzada cuando una operación intenta registrar o vincular un dato único
 * (email, username, customerId o courierId) que ya se encuentra asociado a otro usuario.
 */
public class DuplicateResourceException extends RuntimeException {

    /**
     * Construye una nueva excepción con el mensaje descriptivo especificado.
     *
     * @param message detalle del conflicto por duplicidad detectado.
     */
    public DuplicateResourceException(String message) {
        super(message);
    }
}
