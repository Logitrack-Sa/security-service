package com.logitrack.security.config;

import java.io.File;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * Validador estricto de presencia de secretos obligatorios en tiempo de arranque.
 *
 * <p>Asegura el cumplimiento del contrato de seguridad del Sprint 2:</p>
 * <ul>
 *   <li>Las credenciales de base de datos ({@code DB_PASSWORD}) nunca deben provenir de Git config
 *       y son de suministro obligatorio por variables de entorno en producción.</li>
 *   <li>La clave privada RSA ({@code JWT_PRIVATE_KEY_LOCATION}) debe estar montada desde secretos
 *       y su archivo debe ser accesible.</li>
 *   <li>Las credenciales de administración inicial ({@code SECURITY_ADMIN_PASSWORD}) no pueden ser
 *       valores por defecto ni cadenas vacías en entornos productivos.</li>
 * </ul>
 */
@Configuration
public class SecretValidationConfiguration implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SecretValidationConfiguration.class);

    private final Environment environment;

    /**
     * Construye el componente inyectando el entorno de configuración de Spring.
     *
     * @param environment entorno de propiedades de la aplicación.
     */
    public SecretValidationConfiguration(Environment environment) {
        this.environment = environment;
    }

    /**
     * Ejecuta la validación de secretos al finalizar la inicialización del contexto.
     *
     * @param args argumentos de inicio de la aplicación.
     * @throws IllegalStateException si falta algún secreto requerido en perfil de producción.
     */
    @Override
    public void run(ApplicationArguments args) {
        boolean isProd = environment.matchesProfiles("prod");
        boolean enforceSecrets = isProd || Boolean.parseBoolean(
                environment.getProperty("logitrack.security.secrets.enforce-validation", "false"));

        if (!enforceSecrets) {
            log.info("Validación estricta de secretos en reposo omitida (entorno no productivo)");
            return;
        }

        log.info("Ejecutando validación estricta de secretos obligatorios para perfil productivo...");

        // 1. Validar contraseña de base de datos
        String dbPassword = environment.getProperty("spring.datasource.password");
        if (dbPassword == null || dbPassword.isBlank()) {
            throw new IllegalStateException(
                    "Fallo de arranque: La contraseña de base de datos (DB_PASSWORD) es un secreto obligatorio y no fue suministrada.");
        }

        // 2. Validar ubicación y existencia de la clave privada RSA
        String privateKeyPath = environment.getProperty("logitrack.security.jwt.private-key-location");
        if (privateKeyPath == null || privateKeyPath.isBlank()) {
            throw new IllegalStateException(
                    "Fallo de arranque: La ubicación de la clave privada JWT (JWT_PRIVATE_KEY_LOCATION) es obligatoria en producción.");
        }
        String cleanPath = privateKeyPath.replace("file:", "");
        File privateKeyFile = new File(cleanPath);
        if (!privateKeyFile.exists() || !privateKeyFile.canRead()) {
            throw new IllegalStateException(
                    "Fallo de arranque: El archivo de clave privada JWT en '" + privateKeyPath + "' no existe o no tiene permisos de lectura.");
        }

        // 3. Validar contraseña de administración inicial si la provisión está habilitada
        boolean adminEnabled = Boolean.parseBoolean(environment.getProperty("security.admin.enabled", "false"));
        if (adminEnabled) {
            String adminPassword = environment.getProperty("security.admin.password");
            if (adminPassword == null || adminPassword.isBlank() || "admin123".equals(adminPassword)) {
                throw new IllegalStateException(
                        "Fallo de arranque: Se requiere definir una contraseña segura para SECURITY_ADMIN_PASSWORD distinta al valor por defecto.");
            }
        }

        log.info("Validación de secretos productivos completada exitosamente.");
    }
}
