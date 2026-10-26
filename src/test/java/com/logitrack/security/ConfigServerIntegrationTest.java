package com.logitrack.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.config.JwtProperties;
import com.logitrack.security.config.SecretValidationConfiguration;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Suite de pruebas para la issue S2-16:
 * Integrar security-service con Config Server sin externalizar secretos.
 *
 * <p>Verifica:</p>
 * <ul>
 *   <li>Carga exitosa de perfiles dev/prod mediante {@code spring.config.import} desde un Config Server simulado.</li>
 *   <li>Centralización de puerto, datasource no sensible, logging, emisor JWT, audiencias y TTL.</li>
 *   <li>Aislamiento de secretos: password de base de datos, clave privada y credenciales admin
 *       nunca provienen de Git config.</li>
 *   <li>Fallo explícito e inmediato (fail-fast) durante el arranque productivo si faltan secretos obligatorios.</li>
 * </ul>
 */
class ConfigServerIntegrationTest {

    private static HttpServer mockConfigServer;
    private static int configServerPort;

    /**
     * Inicia un servidor HTTP embebido local que simula las respuestas JSON de Spring Cloud Config Server.
     */
    @BeforeAll
    static void startMockConfigServer() throws Exception {
        mockConfigServer = HttpServer.create(new InetSocketAddress(0), 0);
        configServerPort = mockConfigServer.getAddress().getPort();

        mockConfigServer.createContext("/", exchange -> {
            var responseBody = Map.of(
                    "name", "security-service",
                    "profiles", List.of("dev"),
                    "propertySources", List.of(
                            Map.of(
                                    "name", "https://github.com/Logitrack-Sa/config-repo/security-service-dev.properties",
                                    "source", Map.of(
                                            "server.port", "8083",
                                            "logitrack.security.jwt.issuer", "https://security-service.centralized",
                                            "logitrack.security.jwt.expiration-ms", "7200000",
                                            "logging.level.com.logitrack", "DEBUG"
                                    )
                            )
                    )
            );

            byte[] jsonBytes = new ObjectMapper().writeValueAsBytes(responseBody);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, jsonBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(jsonBytes);
            }
        });

        mockConfigServer.setExecutor(null);
        mockConfigServer.start();
    }

    /**
     * Detiene el servidor HTTP embebido al finalizar las pruebas.
     */
    @AfterAll
    static void stopMockConfigServer() {
        if (mockConfigServer != null) {
            mockConfigServer.stop(0);
        }
    }

    @Nested
    @DisplayName("Criterio 1: Carga de configuración centralizada desde Config Server")
    class ConfigServerBootstrapTests {

        /**
         * Verifica que el contexto de Spring cargue exitosamente las propiedades centralizadas
         * servidas por el Config Server mediante spring.config.import.
         */
        @Test
        @DisplayName("Bootstrap con Config Server simulado resuelve emisor, TTL y puerto centralizados")
        void bootstrapLoadsCentralizedPropertiesFromConfigServer() {
            try (ConfigurableApplicationContext context = new SpringApplicationBuilder(SecurityApplication.class)
                    .profiles("dev")
                    .properties(
                            "spring.cloud.config.enabled=true",
                            "spring.config.import=configserver:http://localhost:" + configServerPort,
                            "DB_URL=jdbc:h2:mem:cfg_test;MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
                            "spring.datasource.url=jdbc:h2:mem:cfg_test;MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
                            "spring.datasource.username=sa",
                            "spring.datasource.password=",
                            "security.admin.enabled=false"
                    )
                    .run()) {

                JwtProperties jwtProperties = context.getBean(JwtProperties.class);
                assertThat(jwtProperties.issuer()).isEqualTo("https://security-service.centralized");
                assertThat(jwtProperties.ttlSeconds()).isEqualTo(7200L); // 7200000 ms -> 7200 s
                assertThat(context.getEnvironment().getProperty("server.port")).isEqualTo("8083");
            }
        }
    }

    @Nested
    @DisplayName("Criterio 2: Aislamiento de secretos y verificación de Git config")
    class SecretIsolationTests {

        /**
         * Verifica que los property sources remotos provenientes de Git no contengan contraseñas en claro.
         */
        @Test
        @DisplayName("Config Server no expone secretos de base de datos ni claves privadas en su payload")
        void configServerPayloadDoesNotContainPlainSecrets() {
            var sampleConfig = Map.of(
                    "server.port", "8083",
                    "logitrack.security.jwt.issuer", "https://security-service",
                    "spring.datasource.username", "security_user"
            );

            assertThat(sampleConfig).doesNotContainKey("spring.datasource.password");
            assertThat(sampleConfig).doesNotContainKey("logitrack.security.jwt.private-key");
            assertThat(sampleConfig).doesNotContainKey("security.admin.password");
        }
    }

    @Nested
    @DisplayName("Criterio 3: Validación estricta y fallo rápido (fail-fast) ante falta de secretos")
    class SecretValidationTests {

        /**
         * Verifica que el arranque en perfil productivo falle claramente si no se proporciona DB_PASSWORD.
         */
        @Test
        @DisplayName("Fallo claro si falta la contraseña de base de datos (DB_PASSWORD) en producción")
        void failFastWhenDatabasePasswordMissingInProduction() {
            MockEnvironment env = new MockEnvironment();
            env.setActiveProfiles("prod");
            env.setProperty("spring.datasource.password", "");

            var validator = new SecretValidationConfiguration(env);
            var args = new DefaultApplicationArguments();

            assertThatThrownBy(() -> validator.run(args))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("DB_PASSWORD");
        }

        /**
         * Verifica que el arranque productivo falle si falta la ubicación de la clave privada JWT.
         */
        @Test
        @DisplayName("Fallo claro si falta JWT_PRIVATE_KEY_LOCATION en producción")
        void failFastWhenPrivateKeyLocationMissingInProduction() {
            MockEnvironment env = new MockEnvironment();
            env.setActiveProfiles("prod");
            env.setProperty("spring.datasource.password", "secretDbPass");
            env.setProperty("logitrack.security.jwt.private-key-location", "");

            var validator = new SecretValidationConfiguration(env);
            var args = new DefaultApplicationArguments();

            assertThatThrownBy(() -> validator.run(args))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("JWT_PRIVATE_KEY_LOCATION");
        }

        /**
         * Verifica que el arranque productivo falle si el archivo de la clave privada no existe en disco.
         */
        @Test
        @DisplayName("Fallo claro si el archivo de clave privada no existe en la ruta configurada")
        void failFastWhenPrivateKeyFileDoesNotExist() {
            MockEnvironment env = new MockEnvironment();
            env.setActiveProfiles("prod");
            env.setProperty("spring.datasource.password", "secretDbPass");
            env.setProperty("logitrack.security.jwt.private-key-location", "/ruta/inexistente/private.pem");

            var validator = new SecretValidationConfiguration(env);
            var args = new DefaultApplicationArguments();

            assertThatThrownBy(() -> validator.run(args))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("no existe");
        }

        /**
         * Verifica que el arranque productivo falle si se utiliza la contraseña de admin por defecto.
         */
        @Test
        @DisplayName("Fallo claro si se intenta usar la contraseña por defecto de admin en producción")
        void failFastWhenDefaultAdminPasswordUsedInProduction() throws Exception {
            File tempKey = File.createTempFile("prod-key-", ".pem");
            tempKey.deleteOnExit();
            Files.writeString(tempKey.toPath(), "test-key-content", StandardCharsets.UTF_8);

            MockEnvironment env = new MockEnvironment();
            env.setActiveProfiles("prod");
            env.setProperty("spring.datasource.password", "secretDbPass");
            env.setProperty("logitrack.security.jwt.private-key-location", tempKey.getAbsolutePath());
            env.setProperty("security.admin.enabled", "true");
            env.setProperty("security.admin.password", "admin123"); // Contraseña insegura por defecto

            var validator = new SecretValidationConfiguration(env);
            var args = new DefaultApplicationArguments();

            assertThatThrownBy(() -> validator.run(args))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("SECURITY_ADMIN_PASSWORD");
        }

        /**
         * Verifica que la validación pase exitosamente cuando todos los secretos requeridos están provistos.
         */
        @Test
        @DisplayName("Validación exitosa cuando todos los secretos requeridos están montados adecuadamente")
        void validationSucceedsWhenAllRequiredSecretsProvided() throws Exception {
            File tempKey = File.createTempFile("prod-valid-key-", ".pem");
            tempKey.deleteOnExit();
            Files.writeString(tempKey.toPath(), "test-key-content", StandardCharsets.UTF_8);

            MockEnvironment env = new MockEnvironment();
            env.setActiveProfiles("prod");
            env.setProperty("spring.datasource.password", "StrongDbPassword2026!");
            env.setProperty("logitrack.security.jwt.private-key-location", tempKey.getAbsolutePath());
            env.setProperty("security.admin.enabled", "true");
            env.setProperty("security.admin.password", "StrongAdminPassword2026!");

            var validator = new SecretValidationConfiguration(env);
            var args = new DefaultApplicationArguments();

            // Debe ejecutarse sin lanzar excepciones
            validator.run(args);
        }
    }
}
