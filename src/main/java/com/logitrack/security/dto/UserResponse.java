package com.logitrack.security.dto;

import com.logitrack.security.entity.Role;
import java.util.Set;
import java.util.UUID;

/**
 * DTO inmutable de respuesta con la información pública y asociaciones del usuario.
 *
 * <p>Diseñado para no exponer bajo ninguna circunstancia contraseñas en texto plano
 * ni hashes criptográficos en respuestas HTTP ni registros de log.</p>
 *
 * @param id identificador único del usuario en security-service.
 * @param email correo electrónico normalizado.
 * @param username nombre de usuario opcional.
 * @param name nombre y apellido o razón social opcional.
 * @param roles conjunto de roles asignados.
 * @param enabled estado de habilitación de la cuenta.
 * @param customerId identificador único de cliente en shipment-service (si está vinculado).
 * @param courierId identificador único de repartidor en courier-service (si está vinculado).
 */
public record UserResponse(
        UUID id,
        String email,
        String username,
        String name,
        Set<Role> roles,
        boolean enabled,
        UUID customerId,
        UUID courierId
) {
    /**
     * Constructor canónico con copia defensiva inmutable del conjunto de roles.
     */
    public UserResponse {
        roles = roles != null ? Set.copyOf(roles) : Set.of();
    }

    /**
     * Constructor de compatibilidad para consultas básicas de usuario.
     *
     * @param id identificador único del usuario.
     * @param email correo electrónico.
     * @param roles conjunto de roles.
     * @param enabled estado activo o inactivo.
     */
    public UserResponse(UUID id, String email, Set<Role> roles, boolean enabled) {
        this(id, email, null, null, roles, enabled, null, null);
    }
}
