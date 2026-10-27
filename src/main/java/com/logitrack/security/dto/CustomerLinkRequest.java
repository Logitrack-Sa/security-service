package com.logitrack.security.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

/**
 * DTO para vincular confiablemente un usuario con un {@code customerId} de dominio.
 *
 * @param customerId identificador único de cliente en shipment-service.
 */
public record CustomerLinkRequest(
        @NotNull(message = "El customerId es obligatorio")
        UUID customerId
) {}
