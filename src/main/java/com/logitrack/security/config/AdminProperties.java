package com.logitrack.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propiedades de configuración para la provisión del administrador inicial por entorno.
 *
 * @param enabled indica si el mecanismo de inicialización automática de ADMIN está activo.
 * @param username nombre de usuario del administrador inicial.
 * @param email correo electrónico del administrador inicial.
 * @param password contraseña provista por variable de entorno o secreto seguro.
 */
@ConfigurationProperties(prefix = "security.admin")
public record AdminProperties(
        boolean enabled,
        String username,
        String email,
        String password
) {}
