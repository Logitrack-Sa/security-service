package com.logitrack.security.dto;

import java.util.List;

/** Contrato paginado de cuentas administrativas; solo expone DTO públicos. */
public record UserPageResponse(List<UserResponse> content, int page, int size,
                               long totalElements, int totalPages) {
    public UserPageResponse { content = List.copyOf(content); }
}
