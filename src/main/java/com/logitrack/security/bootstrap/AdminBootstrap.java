package com.logitrack.security.bootstrap;

import com.logitrack.security.config.AdminProperties;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.repository.UserRepository;
import java.util.Locale;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Componente de inicialización segura para el administrador inicial de la plataforma.
 *
 * <p>Aprovisiona la cuenta con rol {@link Role#ADMIN} utilizando únicamente credenciales
 * suministradas a través de variables de entorno o configuración externa protegida.
 * No registra contraseñas en texto plano ni hashes en los logs del sistema.</p>
 */
@Component
public class AdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AdminProperties properties;

    /**
     * Construye el inicializador con las dependencias requeridas.
     *
     * @param userRepository repositorio de usuarios.
     * @param passwordEncoder codificador de contraseñas BCrypt.
     * @param properties propiedades de provisión de ADMIN inicial.
     */
    public AdminBootstrap(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          AdminProperties properties) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
    }

    /**
     * Ejecuta el proceso de inicialización idempotente al iniciar la aplicación.
     *
     * @param args argumentos de inicio de la aplicación.
     */
    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!properties.enabled() || properties.password() == null || properties.password().isBlank()) {
            log.info("Provisión de ADMIN inicial desactivada o sin contraseña configurada en el entorno.");
            return;
        }

        String email = (properties.email() != null && !properties.email().isBlank())
                ? properties.email().strip().toLowerCase(Locale.ROOT)
                : "admin@logitrack.com";

        String username = (properties.username() != null && !properties.username().isBlank())
                ? properties.username().strip().toLowerCase(Locale.ROOT)
                : "admin";

        if (userRepository.findByEmail(email).isEmpty() && userRepository.findByUsername(username).isEmpty()) {
            String hash = passwordEncoder.encode(properties.password());
            User admin = new User(email, username, "Administrador Inicial", hash, Set.of(Role.ADMIN), null, null);
            userRepository.save(admin);
            log.info("ADMIN inicial provisionado exitosamente para identificador '{}'.", username);
        } else {
            log.info("ADMIN inicial ya se encuentra presente en la base de datos.");
        }
    }
}
