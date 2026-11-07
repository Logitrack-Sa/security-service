package com.logitrack.security.exception;

/** Error público de verificación sin exponer el valor del token. */
public class VerificationTokenException extends RuntimeException {
    private final boolean expired;

    public VerificationTokenException(boolean expired) {
        super(expired ? "El enlace de verificación ha caducado." : "El enlace de verificación no es válido o ya fue utilizado.");
        this.expired = expired;
    }

    public boolean isExpired() {
        return expired;
    }
}
