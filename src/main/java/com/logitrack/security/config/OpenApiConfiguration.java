package com.logitrack.security.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuración de OpenAPI 3 / Swagger para la documentación de los endpoints públicos y administrativos
 * del microservicio {@code security-service}.
 *
 * <p>Define los metadatos globales del servicio, esquema de seguridad mediante tokens Bearer JWT (RS256)
 * y especificaciones conformes a los contratos del Sprint 2 sin exponer credenciales ni claves privadas.</p>
 */
@Configuration
public class OpenApiConfiguration {

    /**
     * Identificador del esquema de seguridad Bearer JWT.
     */
    public static final String BEARER_AUTH = "bearerAuth";

    /**
     * Constructor por defecto para la clase de configuración de OpenAPI.
     */
    public OpenApiConfiguration() {
    }

    /**
     * Define la configuración principal de OpenAPI para security-service.
     *
     * @return instancia de {@link OpenAPI} con información de API y esquema de seguridad JWT.
     */
    @Bean
    public OpenAPI securityServiceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("LogiTrack - security-service")
                        .description("Microservicio de autenticación, gestión de identidades, provisión segura de roles "
                                + "y emisión/verificación descentralizada de tokens JWT RS256 para el ecosistema LogiTrack.")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Equipo de Arquitectura LogiTrack - Seguridad")
                                .email("seguridad@logitrack.com")
                                .url("https://github.com/Logitrack-Sa/security-service"))
                        .license(new License()
                                .name("Uso Interno LogiTrack - Sprint 2")
                                .url("https://github.com/Logitrack-Sa")))
                .components(new Components()
                        .addSecuritySchemes(BEARER_AUTH, new SecurityScheme()
                                .name(BEARER_AUTH)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("Token JWT firmado criptográficamente con RS256 emitido por /api/v1/auth/login. "
                                        + "Incluye sub (UUID de usuario), roles ([ADMIN, CLIENTE, REPARTIDOR]), iss, aud y vínculos confiables.")))
                .addSecurityItem(new SecurityRequirement().addList(BEARER_AUTH));
    }
}
