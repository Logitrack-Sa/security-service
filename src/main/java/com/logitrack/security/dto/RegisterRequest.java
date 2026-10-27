package com.logitrack.security.dto;

import com.logitrack.security.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Set;
import java.util.UUID;

/**
 * DTO para la solicitud de registro público de usuarios.
 *
 * <p>El registro público está restringido exclusivamente a la creación de cuentas con rol {@code CLIENTE}.
 * La inclusión de campos privileged como {@code role}, {@code roles}, {@code customerId} o {@code courierId}
 * es validada para prevenir escalación de privilegios o vinculaciones no autorizadas.</p>
 *
 * @param email dirección de correo electrónico del usuario.
 * @param password contraseña en texto plano (mínimo 8 caracteres).
 * @param username nombre de usuario opcional.
 * @param name nombre descriptivo opcional del usuario.
 * @param role rol solicitado opcional (rechazado si no es CLIENTE).
 * @param roles conjunto de roles opcional (rechazado si no es exclusivamente CLIENTE).
 * @param customerId identificador de cliente opcional (rechazado en registro público).
 * @param courierId identificador de repartidor opcional (rechazado en registro público).
 */
public record RegisterRequest(
        @NotBlank(message = "El email es obligatorio")
        @Email(message = "El formato del email es inválido")
        @Size(max = 254, message = "El email no debe superar los 254 caracteres")
        String email,

        @NotBlank(message = "La contraseña es obligatoria")
        @Size(min = 8, max = 100, message = "La contraseña debe tener entre 8 y 100 caracteres")
        String password,

        @Size(max = 100, message = "El nombre de usuario no debe superar los 100 caracteres")
        String username,

        @Size(max = 200, message = "El nombre no debe superar los 200 caracteres")
        String name,

        String role,

        Set<Role> roles,

        UUID customerId,

        UUID courierId
) {
    /**
     * Constructor canónico con normalización previa de espacios en blanco.
     */
    public RegisterRequest {
        email = email != null ? email.strip() : null;
        username = username != null ? username.strip() : null;
        name = name != null ? name.strip() : null;
        role = role != null ? role.strip() : null;
    }
}
