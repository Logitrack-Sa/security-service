package com.logitrack.security.exception;

public class CustomerProvisioningException extends RuntimeException {
    public CustomerProvisioningException() {
        super("No pudimos preparar tu perfil de cliente. Volvé a intentar iniciar sesión en unos instantes.");
    }
}
