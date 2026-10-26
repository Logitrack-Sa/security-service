package com.logitrack.security.config;

import com.logitrack.security.repository.UserRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración central de seguridad, codificación de contraseñas y autorización HTTP.
 *
 * <p>Define una arquitectura completamente stateless sin sesiones de servidor:</p>
 * <ul>
 *   <li>Deshabilita CSRF para peticiones REST sin estado.</li>
 *   <li>Permite acceso público anónimo a los endpoints de salud (actuator) y registro público (/api/v1/auth/register).</li>
 *   <li>Restringe las operaciones de administración y gestión de identidades (/api/v1/users/**) exclusivamente a usuarios con rol ADMIN.</li>
 *   <li>Deniega por defecto cualquier otra ruta no autorizada explícitamente.</li>
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
     * Cadena de filtros de seguridad HTTP para la protección de endpoints web.
     *
     * @param http constructor de seguridad HTTP.
     * @return cadena de filtros configurada.
     * @throws Exception en caso de error al construir la configuración.
     */
    @Bean
    @ConditionalOnWebApplication
    public SecurityFilterChain security(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/jwks", "/api/v1/auth/public-key").permitAll()
                        .requestMatchers("/api/v1/users", "/api/v1/users/**").hasRole("ADMIN")
                        .anyRequest().denyAll())
                .build();
    }
}
