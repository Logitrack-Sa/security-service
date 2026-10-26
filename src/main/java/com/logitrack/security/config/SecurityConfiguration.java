package com.logitrack.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.dto.ErrorResponse;
import com.logitrack.security.jwt.RsaKeyProvider;
import com.logitrack.security.repository.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Configuración central de seguridad, codificación de contraseñas, validación de JWT y autorización HTTP.
 *
 * <p>Define una arquitectura completamente stateless sin sesiones de servidor:</p>
 * <ul>
 *   <li>Deshabilita CSRF para peticiones REST sin estado.</li>
 *   <li>Permite acceso público anónimo a endpoints de salud (actuator), registro, login y claves públicas (JWKS/PEM).</li>
 *   <li>Exige autenticación mediante Bearer JWT en el endpoint de perfil propio ({@code /api/v1/auth/me}).</li>
 *   <li>Restringe las operaciones de administración y gestión de identidades ({@code /api/v1/users/**}) exclusivamente a usuarios con rol ADMIN.</li>
 *   <li>Responde con errores estandarizados JSON en formato {@link ErrorResponse} ante fallos 401 (no autenticado) y 403 (permisos insuficientes).</li>
 * </ul>
 */
@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties({AdminProperties.class, JwtProperties.class})
public class SecurityConfiguration {

    /**
     * Constructor público para la clase de configuración de seguridad.
     */
    public SecurityConfiguration() {
    }

    /**
     * Codificador criptográfico seguro de contraseñas basado en BCrypt con sal automática.
     *
     * @return instancia de {@link BCryptPasswordEncoder}.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Proveedor de detalles de usuario para la resolución de credenciales y roles.
     *
     * @param userRepository repositorio de persistencia de usuarios.
     * @return servicio {@link UserDetailsService} basado en la base de datos de usuarios.
     */
    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> userRepository.findByEmailIgnoreCaseOrUsernameIgnoreCase(username, username)
                .map(user -> org.springframework.security.core.userdetails.User.builder()
                        .username(user.getEmail())
                        .password(user.getPasswordHash())
                        .disabled(!user.isEnabled())
                        .authorities(user.getRoles().stream()
                                .map(r -> new SimpleGrantedAuthority("ROLE_" + r.name()))
                                .toList())
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con identificador: " + username));
    }

    /**
     * Decodificador de tokens JWT basado en la clave pública RSA y las reglas de contrato del Sprint 2.
     *
     * @param rsaKeyProvider proveedor de claves criptográficas RSA del emisor.
     * @param jwtProperties propiedades de configuración JWT (emisor, audiencias, TTL).
     * @return instancia configurada de {@link JwtDecoder}.
     */
    @Bean
    public JwtDecoder jwtDecoder(RsaKeyProvider rsaKeyProvider, JwtProperties jwtProperties) {
        return com.logitrack.security.jwt.JwtValidation.decoder(rsaKeyProvider, jwtProperties);
    }

    /**
     * Convertidor de claims de JWT a autoridades de Spring Security.
     *
     * <p>Mapea la lista del claim {@code roles} a autoridades con prefijo {@code ROLE_}
     * para posibilitar expresiones de seguridad como {@code hasRole('ADMIN')}.</p>
     *
     * @return convertidor de autenticación JWT configurado.
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Object rolesObj = jwt.getClaims().get("roles");
            if (rolesObj instanceof List<?> roles) {
                return roles.stream()
                        .filter(String.class::isInstance)
                        .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                        .collect(Collectors.toSet());
            }
            return Collections.emptySet();
        });
        return converter;
    }

    /**
     * Manejador de fallos de autenticación (401) para peticiones a recursos protegidos sin JWT válido.
     *
     * @param objectMapper mapeador de JSON para serializar el cuerpo de error.
     * @return instancia de {@link AuthenticationEntryPoint}.
     */
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint(ObjectMapper objectMapper) {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(java.nio.charset.StandardCharsets.UTF_8.name());
            response.setHeader("WWW-Authenticate", "Bearer");
            ErrorResponse error = new ErrorResponse(
                    Instant.now(),
                    HttpStatus.UNAUTHORIZED.value(),
                    HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                    "UNAUTHORIZED",
                    "Token JWT ausente, expirado o con firma inválida",
                    request.getRequestURI()
            );
            response.getWriter().write(objectMapper.writeValueAsString(error));
        };
    }

    /**
     * Manejador de accesos denegados (403) para usuarios autenticados sin privilegios suficientes.
     *
     * @param objectMapper mapeador de JSON para serializar el cuerpo de error.
     * @return instancia de {@link AccessDeniedHandler}.
     */
    @Bean
    public AccessDeniedHandler accessDeniedHandler(ObjectMapper objectMapper) {
        return (request, response, accessDeniedException) -> {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(java.nio.charset.StandardCharsets.UTF_8.name());
            ErrorResponse error = new ErrorResponse(
                    Instant.now(),
                    HttpStatus.FORBIDDEN.value(),
                    HttpStatus.FORBIDDEN.getReasonPhrase(),
                    "FORBIDDEN",
                    "Acceso denegado: permisos insuficientes para la operación solicitada",
                    request.getRequestURI()
            );
            response.getWriter().write(objectMapper.writeValueAsString(error));
        };
    }

    /**
     * Cadena de filtros de seguridad HTTP para la protección de endpoints web.
     *
     * @param http constructor de seguridad HTTP.
     * @param jwtDecoder decodificador de tokens JWT.
     * @param jwtAuthenticationConverter convertidor de roles de JWT.
     * @param authenticationEntryPoint manejador de errores 401.
     * @param accessDeniedHandler manejador de errores 403.
     * @return cadena de filtros configurada.
     * @throws Exception en caso de error al construir la configuración.
     */
    @Bean
    @ConditionalOnWebApplication
    public SecurityFilterChain security(
            HttpSecurity http,
            JwtDecoder jwtDecoder,
            JwtAuthenticationConverter jwtAuthenticationConverter,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler
    ) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/v3/api-docs", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/jwks", "/api/v1/auth/public-key").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/me").authenticated()
                        .requestMatchers("/api/v1/users", "/api/v1/users/**").hasRole("ADMIN")
                        .anyRequest().denyAll())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder)
                                .jwtAuthenticationConverter(jwtAuthenticationConverter))
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .build();
    }
}
