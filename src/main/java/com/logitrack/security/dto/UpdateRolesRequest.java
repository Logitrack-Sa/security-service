package com.logitrack.security.dto;

import com.logitrack.security.entity.Role;
import jakarta.validation.constraints.NotEmpty;
import java.util.Set;

/**
 * DTO para la actualización administrativa de roles de un usuario existente.
 *
 * @param roles conjunto no vacío de roles asignados.
 */
public record UpdateRolesRequest(
        @NotEmpty(message = "El conjunto de roles no puede estar vacío")
        Set<Role> roles
) {}
