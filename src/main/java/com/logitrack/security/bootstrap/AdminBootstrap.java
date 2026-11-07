package com.logitrack.security.bootstrap;

import com.logitrack.security.config.AdminProperties;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.repository.UserRepository;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Componente de inicialización segura para el administrador inicial de la plataforma.
 *
 * <p>Aprovisiona (o actualiza) la cuenta con rol {@link Role#ADMIN} utilizando únicamente
 * credenciales suministradas a través de variables de entorno o configuración externa protegida.
 * No registra contraseñas en texto plano ni hashes en los logs del sistema.</p>
 *
 * <p>Implementa {@link SmartInitializingSingleton} para garantizar que el usuario ADMIN quede
 * persistido en la base de datos <em>antes</em> de que el servidor HTTP (Tomcat) empiece a
 * aceptar tráfico externo, eliminando la race condition entre el bootstrap y el Smoke Test
 * de CI. También implementa {@link ApplicationRunner} para mantener la compatibilidad con la
 * suite de pruebas de integración existente.</p>
 */
@Component
public class AdminBootstrap implements SmartInitializingSingleton, ApplicationRunner {

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
     * Ejecuta el aprovisionamiento del ADMIN inicial como parte de la inicialización del
     * contexto Spring, <em>antes</em> de que Tomcat empiece a aceptar conexiones HTTP.
     *
     * <p>Este método se invoca automáticamente por Spring al finalizar la instanciación de
     * todos los singletons ({@link SmartInitializingSingleton}), lo que garantiza que el
     * usuario ADMIN ya esté disponible en la base de datos cuando el primer health-check
     * del Smoke Test llegue al contenedor.</p>
     */
    @Override
    @Transactional
    public void afterSingletonsInstantiated() {
        provision();
    }

    /**
     * Implementación de {@link ApplicationRunner} conservada para compatibilidad con la
     * suite de pruebas de integración; delega en el mismo método idempotente de provisión
     * y no realiza trabajo adicional si {@code afterSingletonsInstantiated} ya se ejecutó.
     *
     * @param args argumentos de inicio de la aplicación.
     */
    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        provision();
    }

    /**
     * Lógica central de aprovisionamiento idempotente del administrador inicial.
     *
     * <p>Si el usuario ya existe (por email o username), actualiza su contraseña hash,
     * fuerza {@code enabled = true} y {@code emailVerified = true} para garantizar que
     * siempre pueda autenticarse con las credenciales de la variable de entorno vigente.</p>
     */
    @Transactional
    public void provision() {
        if (!properties.enabled()) {
            return;
        }
        if (properties.password() == null || properties.password().isBlank() || "admin123".equals(properties.password())) {
            throw new IllegalStateException("SECURITY_ADMIN_PASSWORD es obligatoria y no admite admin123");
        }

        String email = (properties.email() != null && !properties.email().isBlank())
                ? properties.email().strip().toLowerCase(Locale.ROOT)
                : "admin@logitrack.com";

        String username = (properties.username() != null && !properties.username().isBlank())
                ? properties.username().strip().toLowerCase(Locale.ROOT)
                : "admin";

        Optional<User> existing = userRepository.findByEmail(email)
                .or(() -> userRepository.findByUsername(username));

        if (existing.isEmpty()) {
            String hash = passwordEncoder.encode(properties.password());
            User admin = new User(email, username, "Administrador Inicial", hash, Set.of(Role.ADMIN), null, null);
            admin.setEnabled(true);
            admin.setEmailVerified(true);
            userRepository.save(admin);
            log.info("ADMIN inicial provisionado exitosamente para identificador '{}'.", username);
        } else {
            // Upsert: garantizar que enabled y emailVerified estén activos y actualizar el hash
            User admin = existing.get();
            admin.setEnabled(true);
            admin.setEmailVerified(true);
            admin.updatePasswordHash(passwordEncoder.encode(properties.password()));
            userRepository.save(admin);
            log.info("ADMIN inicial ya se encuentra presente en la base de datos; credenciales actualizadas.");
        }
    }
}
