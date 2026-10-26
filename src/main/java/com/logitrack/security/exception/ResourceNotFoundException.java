package com.logitrack.security.exception;

/**
 * Excepción lanzada cuando un recurso solicitado no existe en la base de datos.
 */
public class ResourceNotFoundException extends RuntimeException {

    /**
     * Construye la excepción con mensaje por defecto.
     */
    public ResourceNotFoundException() {
        super("El recurso no existe");
    }

    /**
     * Construye la excepción con un mensaje personalizado.
     *
     * @param message mensaje explicativo.
     */
    public ResourceNotFoundException(String message) {
        super(message);
    }
}
