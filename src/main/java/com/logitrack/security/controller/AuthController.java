package com.logitrack.security.controller;

import com.logitrack.security.dto.LoginRequest;
import com.logitrack.security.dto.LoginResponse;
import com.logitrack.security.dto.RegisterRequest;
import com.logitrack.security.dto.UserResponse;
import com.logitrack.security.jwt.RsaKeyProvider;
import com.logitrack.security.service.AuthService;
import com.logitrack.security.service.UserService;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Controlador REST para operaciones públicas de autenticación, emisión de tokens y distribución de claves.
 *
 * <p>Expone los siguientes puntos de entrada del contrato del Sprint 2:</p>
 * <ul>
 *   <li>{@code POST /api/v1/auth/register}: Registro público restringido al rol {@code CLIENTE}.</li>
 *   <li>{@code POST /api/v1/auth/login}: Autenticación de credenciales y emisión de JWT RS256.</li>
 *   <li>{@code GET /api/v1/auth/me}: Perfil de identidad del sujeto autenticado mediante JWT.</li>
 *   <li>{@code GET /api/v1/auth/jwks}: Conjunto de claves públicas JWKS (RFC 7517) para validación en consumidores.</li>
 *   <li>{@code GET /api/v1/auth/public-key}: Clave pública en formato PEM y metadatos de versión/kid.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserService userService;
    private final AuthService authService;
    private final RsaKeyProvider rsaKeyProvider;

    /**
     * Construye el controlador inyectando los servicios de usuario, autenticación y proveedor de claves.
     *
     * @param userService servicio de gestión de usuarios.
     * @param authService servicio de autenticación y emisión de tokens.
     * @param rsaKeyProvider proveedor de claves públicas y JWKS.
     */
    public AuthController(UserService userService, AuthService authService, RsaKeyProvider rsaKeyProvider) {
        this.userService = userService;
        this.authService = authService;
        this.rsaKeyProvider = rsaKeyProvider;
    }

    /**
     * Registra un nuevo usuario con rol {@code CLIENTE} de forma pública.
     *
     * @param request datos de registro proporcionados por el cliente.
     * @return respuesta HTTP 201 Created con la información del usuario creado.
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

    /**
     * Autentica credenciales y emite un token JWT firmado según las especificaciones del contrato.
     *
     * @param request credenciales de inicio de sesión (username/email y password).
     * @return respuesta HTTP 200 OK con el token Bearer y su tiempo de vida.
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Retorna el perfil de identidad del sujeto autenticado a partir del token JWT validado.
     *
     * <p>El perfil no contiene hashes de contraseñas ni claves criptográficas.
     * Si el token es inválido, expirado o no se suministra, el filtro de seguridad responde 401.</p>
     *
     * @param jwt token JWT decodificado del contexto de seguridad.
     * @return representación de identidad del usuario autenticado.
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal Jwt jwt) {
        UUID userId = UUID.fromString(jwt.getSubject());
        UserResponse response = userService.findProfileById(userId);
        return ResponseEntity.ok(response);
    }

    /**
     * Expone el conjunto de claves públicas JWKS (RFC 7517) para la verificación de firmas por microservicios.
     *
     * @return conjunto de claves públicas en formato JSON estándar.
     */
    @GetMapping(value = "/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getJwks() {
        return ResponseEntity.ok(rsaKeyProvider.getPublicJwkSet().toJSONObject());
    }

    /**
     * Expone la clave pública RSA en formato PEM y metadatos de algoritmo y clave (kid).
     *
     * @return mapa con el {@code kid}, algoritmo y la clave pública codificada en PEM.
     */
    @GetMapping("/public-key")
    public ResponseEntity<Map<String, String>> getPublicKey() {
        return ResponseEntity.ok(Map.of(
                "kid", rsaKeyProvider.getKeyId(),
                "algorithm", "RS256",
                "publicKey", rsaKeyProvider.getPublicKeyPem()
        ));
    }
}
