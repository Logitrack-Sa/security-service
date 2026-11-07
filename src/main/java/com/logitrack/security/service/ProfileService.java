package com.logitrack.security.service;

import com.logitrack.security.dto.UserResponse;
import java.util.UUID;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

/** Cache-Aside de perfiles por identidad autenticada, nunca por datos elegidos en la petición. */
@Service
public class ProfileService {
    private final UserService users;

    public ProfileService(UserService users) {
        this.users = users;
    }

    /** username es el nombre del principal Spring Security: el UUID del claim sub. */
    @Cacheable(value = "user_profiles", key = "'user::username::' + #username")
    public UserResponse findProfile(String username) {
        return users.findProfileById(UUID.fromString(username));
    }
}
