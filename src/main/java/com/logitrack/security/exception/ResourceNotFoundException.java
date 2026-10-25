package com.logitrack.security.exception;

public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException() { super("El recurso no existe"); }
}
