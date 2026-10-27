package com.logitrack.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Punto de entrada principal para el microservicio {@code security-service}.
 *
 * <p>Responsable de la autenticación, registro de usuarios, control de roles
 * y vinculación de identidades del sistema LogiTrack.</p>
 */
@SpringBootApplication(exclude = org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration.class)
public class SecurityApplication {

    /**
     * Constructor público para la clase principal de la aplicación.
     */
    public SecurityApplication() {
    }

    /**
     * Inicia la aplicación Spring Boot.
     *
     * @param args argumentos de línea de comandos.
     */
    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }
}
