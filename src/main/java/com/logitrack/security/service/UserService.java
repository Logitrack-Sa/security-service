package com.logitrack.security.service;

import com.logitrack.security.dto.UserResponse;
import com.logitrack.security.exception.ResourceNotFoundException;
import com.logitrack.security.repository.UserRepository;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class UserService {
    private final UserRepository users;
    public UserService(UserRepository users) { this.users = users; }

    public UserResponse findById(UUID id) {
        var user = users.findById(id).orElseThrow(ResourceNotFoundException::new);
        return new UserResponse(user.getId(), user.getEmail(), user.getRoles(), user.isEnabled());
    }
}
