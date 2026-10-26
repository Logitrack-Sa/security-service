package com.logitrack.security.service;

import com.logitrack.security.dto.LoginRequest;
import com.logitrack.security.dto.LoginResponse;
import com.logitrack.security.entity.User;
import com.logitrack.security.jwt.JwtTokenService;
import com.logitrack.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Servicio encargado de la validación de credenciales y la emisión de tokens de sesión.
 *
 * <p>Aplica políticas estrictas de seguridad:</p>
 * <ul>
 *   <li>Responde con mensajes genéricos ante cualquier fallo de autenticación para prevenir
 *       ataques de enumeración de usuarios o determinación de estados de habilitación.</li>
 *   <li>Nunca expone ni registra en logs contraseñas en texto plano, hashes criptográficos ni tokens emitidos.</li>
 *   <li>Emite tokens JWT vinculados únicamente al estado real y persistido de la base de datos.</li>
 * </ul>
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;

    /**
     * Construye el servicio inyectando los componentes de persistencia, codificación y emisión de tokens.
     *
     * @param userRepository repositorio de usuarios.
     * @param passwordEncoder codificador criptográfico de contraseñas.
     * @param jwtTokenService servicio de emisión y firma de tokens JWT.
     */
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenService jwtTokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
    }

    /**
     * Autentica las credenciales de un usuario y emite su correspondiente token JWT RS256.
     *
     * @param request datos de la solicitud con identificador y contraseña.
     * @return respuesta de inicio de sesión conteniendo el token Bearer y su tiempo de vida.
     * @throws BadCredentialsException si el usuario no existe, la contraseña es incorrecta,
     *                                 o la cuenta se encuentra deshabilitada.
     */
    @Transactional(readOnly = true)
    public LoginResponse login(LoginRequest request) {
        String identifier = request.getIdentifier();
        if (identifier == null || identifier.isBlank() || request.password() == null || request.password().isBlank()) {
            log.warn("Solicitud de login rechazada: identificador o contraseña ausentes");
            throw new BadCredentialsException("Credenciales inválidas");
        }

        User user = userRepository.findByEmailIgnoreCaseOrUsernameIgnoreCase(identifier, identifier)
                .orElse(null);

        if (user == null) {
            log.warn("Fallo de autenticación: usuario no encontrado para identificador suministrado");
            throw new BadCredentialsException("Credenciales inválidas");
        }

        if (!user.isEnabled()) {
            log.warn("Fallo de autenticación: usuario deshabilitado (id={})", user.getId());
            throw new BadCredentialsException("Credenciales inválidas");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            log.warn("Fallo de autenticación: contraseña incorrecta para usuario (id={})", user.getId());
            throw new BadCredentialsException("Credenciales inválidas");
        }

        String accessToken = jwtTokenService.generateToken(user);
        log.info("Autenticación exitosa y emisión de JWT para usuario (id={})", user.getId());

        return new LoginResponse(accessToken, "Bearer", jwtTokenService.getTtlSeconds());
    }
}
