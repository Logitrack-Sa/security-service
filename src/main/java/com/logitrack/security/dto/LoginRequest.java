package com.logitrack.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.NotBlank;

/**
 * Petición de autenticación de usuario para la emisión de tokens JWT.
 *
 * <p>Permite autenticación indistinta mediante nombre de usuario ({@code username})
 * o correo electrónico ({@code email}), acompañado de la contraseña en texto plano
 * para ser validada contra el hash seguro almacenado.</p>
 *
 * @param username nombre de usuario opcional si se suministra el email.
 * @param email dirección de correo electrónico opcional si se suministra el username.
 * @param password contraseña obligatoria del usuario.
 */
public record LoginRequest(
        String username,
        String email,
        @NotBlank(message = "La contraseña es obligatoria")
        String password
) {

    /**
     * Constructor canónico con normalización defensiva de cadenas de texto.
     *
     * @param username nombre de usuario sin espacios superfluos.
     * @param email correo electrónico sin espacios superfluos.
     * @param password contraseña del usuario.
     */
    public LoginRequest {
        username = username != null ? username.strip() : null;
        email = email != null ? email.strip() : null;
    }

    /**
     * Resuelve el identificador de inicio de sesión preferido (username o email).
     *
     * @return identificador no vacío, o {@code null} si ninguno fue suministrado.
     */
    @JsonIgnore
    public String getIdentifier() {
        if (username != null && !username.isBlank()) {
            return username;
        }
        if (email != null && !email.isBlank()) {
            return email;
        }
        return null;
    }
}
