package com.logitrack.security.dto;

import com.logitrack.security.entity.Role;
import java.util.Set;
import java.util.UUID;

public record UserResponse(UUID id, String email, Set<Role> roles, boolean enabled) {
    public UserResponse { roles = Set.copyOf(roles); }
}
