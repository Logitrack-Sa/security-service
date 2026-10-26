package com.logitrack.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Suite de pruebas para la especificación y documentación pública OpenAPI 3 (Issue S2-20).
 *
 * <p>Verifica que el contrato OpenAPI exponga todas las rutas públicas y de administración
 * de identidad sin revelar contraseñas reales, hashes criptográficos ni claves privadas.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class OpenApiDocumentationTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    /**
     * Verifica que el endpoint /v3/api-docs responda 200 OK y genere una especificación
     * OpenAPI 3 válida con título, esquemas de seguridad y sin secretos reales.
     *
     * @throws Exception en caso de fallo en la llamada HTTP o análisis del JSON.
     */
    @Test
    @DisplayName("GET /v3/api-docs expone la especificación OpenAPI 3 completa sin secretos")
    void openApiSpecificationIsGeneratedAndSecure() throws Exception {
        MvcResult result = http.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn();

        String content = result.getResponse().getContentAsString();
        JsonNode root = json.readTree(content);

        // 1. Verificación de metadatos generales
        assertThat(root.has("openapi")).isTrue();
        assertThat(root.get("info").get("title").asText()).isEqualTo("LogiTrack - security-service");
        assertThat(root.get("info").get("version").asText()).isEqualTo("1.0.0");

        // 2. Verificación de rutas de autenticación y de usuario
        JsonNode paths = root.get("paths");
        assertThat(paths.has("/api/v1/auth/register")).isTrue();
        assertThat(paths.get("/api/v1/auth/register").has("post")).isTrue();

        assertThat(paths.has("/api/v1/auth/login")).isTrue();
        assertThat(paths.get("/api/v1/auth/login").has("post")).isTrue();

        assertThat(paths.has("/api/v1/auth/me")).isTrue();
        assertThat(paths.get("/api/v1/auth/me").has("get")).isTrue();

        assertThat(paths.has("/api/v1/auth/jwks")).isTrue();
        assertThat(paths.get("/api/v1/auth/jwks").has("get")).isTrue();

        assertThat(paths.has("/api/v1/auth/public-key")).isTrue();
        assertThat(paths.get("/api/v1/auth/public-key").has("get")).isTrue();

        assertThat(paths.has("/api/v1/users/{id}")).isTrue();
        assertThat(paths.has("/api/v1/users")).isTrue();
        assertThat(paths.has("/api/v1/users/{id}/roles")).isTrue();
        assertThat(paths.has("/api/v1/users/{id}/customer-link")).isTrue();
        assertThat(paths.has("/api/v1/users/{id}/courier-link")).isTrue();

        // 3. Verificación de esquemas de datos
        JsonNode schemas = root.get("components").get("schemas");
        assertThat(schemas.has("RegisterRequest")).isTrue();
        assertThat(schemas.has("LoginRequest")).isTrue();
        assertThat(schemas.has("LoginResponse")).isTrue();
        assertThat(schemas.has("UserResponse")).isTrue();
        assertThat(schemas.has("ErrorResponse")).isTrue();
        assertThat(schemas.has("CreateUserRequest")).isTrue();

        // 4. Verificación del esquema de seguridad Bearer JWT
        JsonNode securitySchemes = root.get("components").get("securitySchemes");
        assertThat(securitySchemes.has("bearerAuth")).isTrue();
        JsonNode bearerAuth = securitySchemes.get("bearerAuth");
        assertThat(bearerAuth.get("type").asText()).isEqualTo("http");
        assertThat(bearerAuth.get("scheme").asText()).isEqualTo("bearer");
        assertThat(bearerAuth.get("bearerFormat").asText()).isEqualTo("JWT");

        // 5. Verificación de estricta confidencialidad (cero secretos en la especificación)
        assertThat(content).doesNotContain("PRIVATE KEY");
        assertThat(content).doesNotContain("$2a$10$");
        assertThat(content).doesNotContain("$2b$10$");
        assertThat(content).doesNotContain("password_hash");
    }

    /**
     * Verifica que Swagger UI esté disponible de forma pública.
     *
     * @throws Exception en caso de fallo en la petición HTTP.
     */
    @Test
    @DisplayName("GET /swagger-ui/index.html responde 200 OK de forma pública")
    void swaggerUiIsPubliclyAccessible() throws Exception {
        http.perform(get("/swagger-ui/index.html"))
                .andExpect(status().isOk());
    }
}
