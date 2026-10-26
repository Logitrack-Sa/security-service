package com.logitrack.security.dto;

import com.logitrack.security.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.Set;
import java.util.UUID;

/**
 * DTO para la creación administrativa de usuarios por parte de un usuario con rol ADMIN.
 *
 * <p>Permite dar de alta cuentas con cualquier combinación válida de roles (ADMIN, CLIENTE, REPARTIDOR)
 * y establecer de forma confiable vínculos opcionales a {@code customerId} o {@code courierId}.</p>
 *
 * @param email dirección de correo electrónico.
 * @param password contraseña inicial (mínimo 8 caracteres).
 * @param username nombre de usuario opcional.
 * @param name nombre descriptivo opcional.
 * @param roles conjunto no vacío de roles asignados.
 * @param customerId identificador único de cliente opcional.
 * @param courierId identificador único de repartidor opcional.
 */
public record CreateUserRequest(
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

        @NotEmpty(message = "Debe asignar al menos un rol al usuario")
        Set<Role> roles,

        UUID customerId,

        UUID courierId
) {
    /**
     * Constructor canónico con normalización previa de espacios en blanco.
     */
    public CreateUserRequest {
        email = email != null ? email.strip() : null;
        username = username != null ? username.strip() : null;
        name = name != null ? name.strip() : null;
    }
}
