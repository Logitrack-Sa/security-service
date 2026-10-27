package com.logitrack.security.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

/**
 * DTO para vincular confiablemente un usuario con un {@code courierId} de dominio.
 *
 * @param courierId identificador único de repartidor en courier-service.
 */
public record CourierLinkRequest(
        @NotNull(message = "El courierId es obligatorio")
        UUID courierId
) {}
