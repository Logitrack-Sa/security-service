package com.logitrack.security.controller;

import com.logitrack.security.dto.RegisterRequest;
import com.logitrack.security.dto.UserResponse;
import com.logitrack.security.service.UserService;
import jakarta.validation.Valid;
import java.net.URI;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Controlador REST para operaciones públicas de autenticación y registro.
 *
 * <p>Expone el punto de entrada para el registro público de nuevos usuarios bajo el contrato
 * del Sprint 2. El registro público solo permite la creación de usuarios con rol {@code CLIENTE}
 * y rechaza intentos de elevar privilegios a {@code ADMIN} o {@code REPARTIDOR}, o de vincular
 * identidades de dominio arbitrarias en el payload.</p>
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserService userService;

    /**
     * Construye el controlador inyectando el servicio de usuarios.
     *
     * @param userService servicio de gestión de usuarios.
     */
    public AuthController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Registra un nuevo usuario con rol {@code CLIENTE} de forma pública.
     *
     * @param request datos de registro proporcionados por el cliente.
     * @return respuesta HTTP 201 Created con la información del usuario creado (sin hashes ni contraseñas).
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse response = userService.registerPublic(request);
        URI location = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/api/v1/users/{id}")
                .buildAndExpand(response.id())
                .toUri();
        return ResponseEntity.created(location).body(response);
    }
}
