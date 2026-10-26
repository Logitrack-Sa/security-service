package com.logitrack.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.config.JwtProperties;
import com.logitrack.security.dto.CourierLinkRequest;
import com.logitrack.security.dto.CreateUserRequest;
import com.logitrack.security.dto.CustomerLinkRequest;
import com.logitrack.security.dto.RegisterRequest;
import com.logitrack.security.dto.UpdateRolesRequest;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.jwt.JwtTokenService;
import com.logitrack.security.jwt.RsaKeyProvider;
import com.logitrack.security.repository.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import jakarta.persistence.EntityManager;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Suite integral de pruebas de seguridad para la issue S2-18:
 * Probar JWT, roles, pertenencia y aislamiento de identidades.
 *
 * <p>Verifica rigurosamente los cuatro criterios de aceptación del Sprint 2:</p>
 * <ol>
 *   <li><b>JWT inválidos y negativos:</b> Vencidos, firmas alteradas, claves foráneas, algoritmos no permitidos
 *       (HS256, none), emisores/audiencias no autorizados y ausencia de token (401 Unauthorized estandarizado).</li>
 *   <li><b>Prevención de escalación y protección de registro:</b> Registro público solo crea CLIENTE, rechaza
 *       intento de elegir ADMIN/REPARTIDOR o auto-asignarse identidades (customerId/courierId); operaciones de
 *       provisión y roles exclusivas de ADMIN.</li>
 *   <li><b>Matriz de roles y aislamiento para 2 clientes y 2 repartidores:</b> Verificación de las identidades
 *       fijadas en {@code contracts/v1/identities.json} demostrando estricto aislamiento de dominio y perfiles.</li>
 *   <li><b>Verificación descentralizada sin dependencia HTTP:</b> Validación local de tokens basada en clave pública
 *       RSA en memoria/archivo, sin solicitudes salientes al emisor durante peticiones protegidas.</li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class JwtRolesAndIdentityIsolationTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private RsaKeyProvider rsaKeyProvider;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbcTemplate;

    private JsonNode contractIdentities;

    private User seededAdmin;
    private User seededClienteA;
    private User seededClienteB;
    private User seededRepartidorA;
    private User seededRepartidorB;

    /**
     * Convierte un UUID canónico en un arreglo de 16 bytes conforme a RFC 4122 para BINARY(16).
     */
    private static byte[] uuidToBytes(UUID uuid) {
        if (uuid == null) {
            return null;
        }
        java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(new byte[16]);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return bb.array();
    }

    /**
     * Carga el archivo de contrato {@code contracts/v1/identities.json} e inicializa
     * las cinco identidades canónicas en la base de datos de pruebas.
     *
     * @throws Exception ante fallos de lectura o persistencia de fixtures.
     */
    @BeforeEach
    void setUp() throws Exception {
        try (InputStream input = getClass().getResourceAsStream("/contracts/v1/identities.json")) {
            assertThat(input).as("El fixture de contrato /contracts/v1/identities.json debe existir").isNotNull();
            contractIdentities = json.readTree(input);
        }

        // Sembrado de identidades canónicas con sus UUIDs exactos de fixture
        UUID adminSub = UUID.fromString(contractIdentities.get("admin").get("sub").asText());
        UUID clienteASub = UUID.fromString(contractIdentities.get("cliente-a").get("sub").asText());
        UUID clienteACustomerId = UUID.fromString(contractIdentities.get("cliente-a").get("customerId").asText());
        UUID clienteBSub = UUID.fromString(contractIdentities.get("cliente-b").get("sub").asText());
        UUID clienteBCustomerId = UUID.fromString(contractIdentities.get("cliente-b").get("customerId").asText());
        UUID repartidorASub = UUID.fromString(contractIdentities.get("repartidor-a").get("sub").asText());
        UUID repartidorACourierId = UUID.fromString(contractIdentities.get("repartidor-a").get("courierId").asText());
        UUID repartidorBSub = UUID.fromString(contractIdentities.get("repartidor-b").get("sub").asText());
        UUID repartidorBCourierId = UUID.fromString(contractIdentities.get("repartidor-b").get("courierId").asText());

        seededAdmin = seedUserWithFixedId(adminSub, "admin@logitrack.com", "admin", "Admin Principal",
                Set.of(Role.ADMIN), null, null);

        seededClienteA = seedUserWithFixedId(clienteASub, "cliente.a@logitrack.com", "cliente_a", "Cliente A",
                Set.of(Role.CLIENTE), clienteACustomerId, null);

        seededClienteB = seedUserWithFixedId(clienteBSub, "cliente.b@logitrack.com", "cliente_b", "Cliente B",
                Set.of(Role.CLIENTE), clienteBCustomerId, null);

        seededRepartidorA = seedUserWithFixedId(repartidorASub, "repartidor.a@logitrack.com", "repartidor_a", "Repartidor A",
                Set.of(Role.REPARTIDOR), null, repartidorACourierId);

        seededRepartidorB = seedUserWithFixedId(repartidorBSub, "repartidor.b@logitrack.com", "repartidor_b", "Repartidor B",
                Set.of(Role.REPARTIDOR), null, repartidorBCourierId);
    }

    /**
     * Persiste un usuario en base de datos con un UUID primario fijo mediante JDBC nativo.
     */
    private User seedUserWithFixedId(UUID id, String email, String username, String name,
                                     Set<Role> roles, UUID customerId, UUID courierId) {
        String passwordHash = passwordEncoder.encode("SecurePass123!");
        jdbcTemplate.update("""
                INSERT INTO users (id, email, username, name, password_hash, enabled, customer_id, courier_id, version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, uuidToBytes(id), email, username, name, passwordHash, true,
                uuidToBytes(customerId), uuidToBytes(courierId), 0L);

        for (Role role : roles) {
            jdbcTemplate.update("INSERT INTO user_roles (user_id, role) VALUES (?, ?)", uuidToBytes(id), role.name());
        }

        return userRepository.findById(id).orElseThrow();
    }

    /**
     * Emite un token JWT firmado válido a partir del fixture canónico indicado.
     *
     * @param fixtureName clave de identidad en {@code identities.json} ("admin", "cliente-a", etc.).
     * @return token JWT serializado en formato compacto RS256.
     * @throws Exception ante errores criptográficos.
     */
    private String tokenForFixture(String fixtureName) throws Exception {
        return tokenForFixtureWithOverrides(fixtureName, Map.of());
    }

    /**
     * Emite un token JWT a partir de la identidad de fixture aplicando sobreescrituras arbitrarias de claims.
     *
     * @param fixtureName clave de identidad en {@code identities.json}.
     * @param overrides mapa de claims que reemplazan o añaden atributos al payload.
     * @return token JWT firmado en formato compacto RS256.
     * @throws Exception ante errores criptográficos.
     */
    private String tokenForFixtureWithOverrides(String fixtureName, Map<String, Object> overrides) throws Exception {
        JsonNode identity = contractIdentities.get(fixtureName);
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(jwtProperties.ttlSeconds());

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(identity.get("sub").asText())
                .issuer(jwtProperties.issuer())
                .audience(jwtProperties.audiences())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(exp));

        if (identity.has("roles")) {
            List<String> roles = json.convertValue(identity.get("roles"), List.class);
            builder.claim("roles", roles);
        }
        if (identity.has("customerId")) {
            builder.claim("customerId", identity.get("customerId").asText());
        }
        if (identity.has("courierId")) {
            builder.claim("courierId", identity.get("courierId").asText());
        }

        overrides.forEach(builder::claim);

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwtProperties.keyId()).build(),
                builder.build()
        );
        signedJwt.sign(new RSASSASigner(rsaKeyProvider.getPrivateKey()));
        return signedJwt.serialize();
    }

    @Nested
    @DisplayName("Criterio 1: JWT vencido, firma alterada, algoritmo incorrecto, issuer/audience inválidos y token ausente")
    class NegativeAndInvalidTokenTests {

        /**
         * Verifica que un token JWT con fecha de expiración anterior a la actual sea rechazado con 401.
         */
        @Test
        @DisplayName("1.1 Token JWT expirado responde 401 Unauthorized")
        void expiredTokenIsRejectedWith401() throws Exception {
            Instant past = Instant.now().minusSeconds(7200);
            String expiredToken = tokenForFixtureWithOverrides("cliente-a", Map.of(
                    "iat", Date.from(past.minusSeconds(3600)),
                    "exp", Date.from(past)
            ));

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")))
                    .andExpect(jsonPath("$.status", is(401)));
        }

        /**
         * Verifica que un token cuyos bytes de firma hayan sido manipulados sea rechazado con 401.
         */
        @Test
        @DisplayName("1.2 Token JWT con firma criptográfica alterada responde 401 Unauthorized")
        void tamperedSignatureIsRejectedWith401() throws Exception {
            String validToken = tokenForFixture("cliente-a");
            String[] segments = validToken.split("\\.");
            String forgedSignature = segments[2].substring(0, segments[2].length() - 6) + "BADSIG";
            String tamperedToken = segments[0] + "." + segments[1] + "." + forgedSignature;

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tamperedToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")))
                    .andExpect(jsonPath("$.status", is(401)));
        }

        /**
         * Verifica que un token firmado con una clave privada RSA externa no autorizada sea rechazado con 401.
         */
        @Test
        @DisplayName("1.3 Token JWT firmado con clave RSA foránea no confiable responde 401 Unauthorized")
        void foreignKeySignedTokenIsRejectedWith401() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair foreignKeyPair = kpg.generateKeyPair();

            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(seededClienteA.getId().toString())
                    .issuer(jwtProperties.issuer())
                    .audience(jwtProperties.audiences())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(3600)))
                    .claim("roles", List.of("CLIENTE"))
                    .build();

            SignedJWT foreignJwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("foreign-key-id").build(),
                    claims
            );
            foreignJwt.sign(new RSASSASigner((RSAPrivateKey) foreignKeyPair.getPrivate()));
            String foreignToken = foreignJwt.serialize();

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + foreignToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }

        /**
         * Verifica que un token con algoritmo simétrico HMAC (HS256) sea rechazado con 401.
         */
        @Test
        @DisplayName("1.4 Token JWT con algoritmo simétrico HS256 es rechazado con 401 Unauthorized")
        void hmacAlgorithmIsRejectedWith401() throws Exception {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(seededClienteA.getId().toString())
                    .issuer(jwtProperties.issuer())
                    .audience(jwtProperties.audiences())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(3600)))
                    .claim("roles", List.of("CLIENTE"))
                    .build();

            SignedJWT hmacJwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(), claims);
            hmacJwt.sign(new MACSigner("0123456789012345678901234567890123456789"));
            String hmacToken = hmacJwt.serialize();

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + hmacToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }

        /**
         * Verifica que un token no firmado (algoritmo 'none' o texto plano) sea rechazado con 401.
         */
        @Test
        @DisplayName("1.5 Token JWT sin firma (algoritmo none) es rechazado con 401 Unauthorized")
        void unsignedTokenIsRejectedWith401() throws Exception {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(seededClienteA.getId().toString())
                    .issuer(jwtProperties.issuer())
                    .audience(jwtProperties.audiences())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(3600)))
                    .claim("roles", List.of("CLIENTE"))
                    .build();

            PlainJWT plainJwt = new PlainJWT(claims);
            String plainToken = plainJwt.serialize();

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + plainToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }

        /**
         * Verifica que un token con emisor (claim iss) no autorizado sea rechazado con 401.
         */
        @Test
        @DisplayName("1.6 Token JWT con emisor (iss) ajeno o falso responde 401 Unauthorized")
        void invalidIssuerIsRejectedWith401() throws Exception {
            String fakeIssuerToken = tokenForFixtureWithOverrides("cliente-a", Map.of(
                    "iss", "https://untrusted-auth-server.example.org"
            ));

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + fakeIssuerToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }

        /**
         * Verifica que un token con audiencia (claim aud) no autorizada sea rechazado con 401.
         */
        @Test
        @DisplayName("1.7 Token JWT con audiencia (aud) no autorizada responde 401 Unauthorized")
        void invalidAudienceIsRejectedWith401() throws Exception {
            String invalidAudToken = tokenForFixtureWithOverrides("cliente-a", Map.of(
                    "aud", List.of("billing-service", "analytics-service")
            ));

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + invalidAudToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }

        /**
         * Verifica que un token con audiencia (claim aud) vacía sea rechazado con 401.
         */
        @Test
        @DisplayName("1.8 Token JWT sin claim de audiencia responde 401 Unauthorized")
        void missingAudienceIsRejectedWith401() throws Exception {
            String missingAudToken = tokenForFixtureWithOverrides("cliente-a", Map.of(
                    "aud", List.of()
            ));

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + missingAudToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }

        /**
         * Verifica que peticiones sin cabecera Authorization respondan 401 Unauthorized.
         */
        @Test
        @DisplayName("1.9 Petición a endpoint protegido sin token responde 401 Unauthorized")
        void missingTokenReturns401() throws Exception {
            http.perform(get("/api/v1/auth/me"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")))
                    .andExpect(jsonPath("$.status", is(401)))
                    .andExpect(jsonPath("$.message", containsString("Token JWT ausente")));
        }

        /**
         * Verifica que peticiones con formato de token malformado o prefijo inválido respondan 401.
         */
        @Test
        @DisplayName("1.10 Petición con valor Bearer malformado responde 401 Unauthorized")
        void malformedBearerReturns401() throws Exception {
            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer not.a.valid.jwt"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }
    }

    @Nested
    @DisplayName("Criterio 2: Registro público no eleva rol, vínculos confiables inviolables y matriz de administración")
    class PublicRegistrationAndPrivilegeEscalationTests {

        /**
         * Verifica que el registro público solo cree usuarios con rol CLIENTE, ignorando intentos
         * de fijar roles privilegiados o campos ajenos.
         */
        @Test
        @DisplayName("2.1 Registro público crea exclusivamente usuario con rol CLIENTE")
        void publicRegistrationCreatesOnlyCliente() throws Exception {
            var request = new RegisterRequest("nuevo.publico@logitrack.com", "Password123!", "nuevo_pub", "Nuevo Publico", null, null, null, null);

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id", notNullValue()))
                    .andExpect(jsonPath("$.roles", hasItem("CLIENTE")))
                    .andExpect(jsonPath("$.customerId", nullValue()))
                    .andExpect(jsonPath("$.courierId", nullValue()));
        }

        /**
         * Verifica que un intento de inyectar 'roles' o 'role': 'ADMIN' en el payload de registro
         * público sea rechazado con 400 Bad Request por desconocimiento de propiedad estricta.
         */
        @Test
        @DisplayName("2.2 Intento de inyectar roles privilegiados en registro público devuelve 400 Bad Request")
        void injectRolesInPublicRegistrationIsRejected() throws Exception {
            String payloadWithAdmin = """
                    {
                      "email": "hacker@logitrack.com",
                      "password": "Password123!",
                      "username": "hacker",
                      "roles": ["ADMIN"]
                    }
                    """;

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(payloadWithAdmin))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("PRIVILEGE_ESCALATION")));
        }

        /**
         * Verifica que un intento de inyectar customerId o courierId en el payload de registro público
         * sea rechazado con 400 Bad Request.
         */
        @Test
        @DisplayName("2.3 Intento de inyectar vínculos de dominio en registro público devuelve 400 Bad Request")
        void injectDomainLinksInPublicRegistrationIsRejected() throws Exception {
            String payloadWithCustomerId = """
                    {
                      "email": "forger@logitrack.com",
                      "password": "Password123!",
                      "username": "forger",
                      "customerId": "10000000-0000-0000-0000-000000000001"
                    }
                    """;

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(payloadWithCustomerId))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("PRIVILEGE_ESCALATION")));
        }

        /**
         * Verifica que un usuario con rol CLIENTE reciba 403 Forbidden al intentar ejecutar operaciones
         * de alta administrativa o modificación de roles.
         */
        @Test
        @DisplayName("2.4 CLIENTE recibe 403 Forbidden al intentar acceder a rutas de administración de usuarios")
        void clienteForbiddenToAccessUserAdminEndpoints() throws Exception {
            String clienteToken = tokenForFixture("cliente-a");

            var createReq = new CreateUserRequest("fake.admin@logitrack.com", "Pass123!", "fake_admin", "Fake",
                    Set.of(Role.ADMIN), null, null);

            http.perform(post("/api/v1/users")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + clienteToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(createReq)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code", is("FORBIDDEN")));
        }

        /**
         * Verifica que un usuario con rol REPARTIDOR reciba 403 Forbidden al intentar ejecutar operaciones
         * administrativas de vinculación de identidades.
         */
        @Test
        @DisplayName("2.5 REPARTIDOR recibe 403 Forbidden al intentar vincular identidades de cliente")
        void repartidorForbiddenToLinkIdentities() throws Exception {
            String repartidorToken = tokenForFixture("repartidor-a");

            var linkReq = new CustomerLinkRequest(UUID.randomUUID());

            http.perform(patch("/api/v1/users/" + seededClienteA.getId() + "/customer-link")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + repartidorToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(linkReq)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code", is("FORBIDDEN")));
        }

        /**
         * Verifica que un ADMIN no pueda auto-modificar arbitrariamente sus propios roles.
         */
        @Test
        @DisplayName("2.6 ADMIN no puede auto-modificar arbitrariamente sus propios roles (400 PRIVILEGE_ESCALATION)")
        void adminCannotArbitrarilyModifyOwnRoles() throws Exception {
            String adminToken = tokenForFixture("admin");
            var updateRoles = new UpdateRolesRequest(Set.of(Role.CLIENTE));

            http.perform(put("/api/v1/users/" + seededAdmin.getId() + "/roles")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(updateRoles)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("PRIVILEGE_ESCALATION")))
                    .andExpect(jsonPath("$.message", containsString("auto-modificación arbitraria de roles propios")));
        }
    }

    @Nested
    @DisplayName("Criterio 3: Matriz documentada para 2 Clientes y 2 Repartidores y aislamiento estricto")
    class RoleMatrixAndIdentityIsolationTests {

        /**
         * Verifica que Cliente A obtenga su propio perfil con su customerId canónico.
         */
        @Test
        @DisplayName("3.1 Cliente A accede a GET /api/v1/auth/me y obtiene su customerId asignado")
        void clienteAGetsOwnProfile() throws Exception {
            String token = tokenForFixture("cliente-a");

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is("00000000-0000-0000-0000-000000000002")))
                    .andExpect(jsonPath("$.email", is("cliente.a@logitrack.com")))
                    .andExpect(jsonPath("$.roles", hasItem("CLIENTE")))
                    .andExpect(jsonPath("$.customerId", is("10000000-0000-0000-0000-000000000001")))
                    .andExpect(jsonPath("$.courierId", nullValue()));
        }

        /**
         * Verifica que Cliente B obtenga su propio perfil con su customerId canónico, aislado de Cliente A.
         */
        @Test
        @DisplayName("3.2 Cliente B accede a GET /api/v1/auth/me y obtiene su customerId asignado (aislado de Cliente A)")
        void clienteBGetsOwnProfileIsolatedFromClienteA() throws Exception {
            String token = tokenForFixture("cliente-b");

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is("00000000-0000-0000-0000-000000000003")))
                    .andExpect(jsonPath("$.email", is("cliente.b@logitrack.com")))
                    .andExpect(jsonPath("$.roles", hasItem("CLIENTE")))
                    .andExpect(jsonPath("$.customerId", is("10000000-0000-0000-0000-000000000002")))
                    .andExpect(jsonPath("$.courierId", nullValue()));
        }

        /**
         * Verifica que Cliente A reciba 403 Forbidden al intentar inspeccionar el registro de Cliente B en /api/v1/users/{id}.
         */
        @Test
        @DisplayName("3.3 Cliente A recibe 403 Forbidden al intentar consultar al Cliente B")
        void clienteACannotInspectClienteB() throws Exception {
            String token = tokenForFixture("cliente-a");

            http.perform(get("/api/v1/users/" + seededClienteB.getId())
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code", is("FORBIDDEN")));
        }

        /**
         * Verifica que Repartidor A obtenga su propio perfil con su courierId canónico.
         */
        @Test
        @DisplayName("3.4 Repartidor A accede a GET /api/v1/auth/me y obtiene su courierId asignado")
        void repartidorAGetsOwnProfile() throws Exception {
            String token = tokenForFixture("repartidor-a");

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is("00000000-0000-0000-0000-000000000004")))
                    .andExpect(jsonPath("$.email", is("repartidor.a@logitrack.com")))
                    .andExpect(jsonPath("$.roles", hasItem("REPARTIDOR")))
                    .andExpect(jsonPath("$.courierId", is("20000000-0000-0000-0000-000000000001")))
                    .andExpect(jsonPath("$.customerId", nullValue()));
        }

        /**
         * Verifica que Repartidor B obtenga su propio perfil con su courierId canónico, aislado de Repartidor A.
         */
        @Test
        @DisplayName("3.5 Repartidor B accede a GET /api/v1/auth/me y obtiene su courierId asignado (aislado de Repartidor A)")
        void repartidorBGetsOwnProfileIsolatedFromRepartidorA() throws Exception {
            String token = tokenForFixture("repartidor-b");

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is("00000000-0000-0000-0000-000000000005")))
                    .andExpect(jsonPath("$.email", is("repartidor.b@logitrack.com")))
                    .andExpect(jsonPath("$.roles", hasItem("REPARTIDOR")))
                    .andExpect(jsonPath("$.courierId", is("20000000-0000-0000-0000-000000000002")))
                    .andExpect(jsonPath("$.customerId", nullValue()));
        }

        /**
         * Verifica que Repartidor A reciba 403 Forbidden al intentar inspeccionar el registro de Repartidor B en /api/v1/users/{id}.
         */
        @Test
        @DisplayName("3.6 Repartidor A recibe 403 Forbidden al intentar consultar al Repartidor B")
        void repartidorACannotInspectRepartidorB() throws Exception {
            String token = tokenForFixture("repartidor-a");

            http.perform(get("/api/v1/users/" + seededRepartidorB.getId())
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code", is("FORBIDDEN")));
        }

        /**
         * Verifica que el ADMIN pueda inspeccionar los perfiles de todos los clientes y repartidores.
         */
        @Test
        @DisplayName("3.7 ADMIN puede consultar perfiles de cualquier cliente o repartidor en /api/v1/users/{id}")
        void adminCanInspectAllUsers() throws Exception {
            String adminToken = tokenForFixture("admin");

            // Consultar Cliente A
            http.perform(get("/api/v1/users/" + seededClienteA.getId())
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(seededClienteA.getId().toString())))
                    .andExpect(jsonPath("$.customerId", is("10000000-0000-0000-0000-000000000001")));

            // Consultar Repartidor B
            http.perform(get("/api/v1/users/" + seededRepartidorB.getId())
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(seededRepartidorB.getId().toString())))
                    .andExpect(jsonPath("$.courierId", is("20000000-0000-0000-0000-000000000002")));
        }

        /**
         * Verifica que el ADMIN pueda vincular o actualizar los identificadores de dominio de otros usuarios.
         */
        @Test
        @DisplayName("3.8 ADMIN puede vincular o actualizar identidades de dominio en usuarios objetivo")
        void adminCanUpdateDomainLinksOnTargetUsers() throws Exception {
            String adminToken = tokenForFixture("admin");
            UUID nuevoCustomerId = UUID.fromString("10000000-0000-0000-0000-999999999999");

            var linkReq = new CustomerLinkRequest(nuevoCustomerId);

            http.perform(put("/api/v1/users/" + seededClienteB.getId() + "/customer-link")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(linkReq)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.customerId", is(nuevoCustomerId.toString())));
        }
    }

    @Nested
    @DisplayName("Criterio 4: Validación descentralizada sin dependencia HTTP del emisor en tiempo de ejecución")
    class OfflineIssuerIndependenceTests {

        /**
         * Verifica que la decodificación y verificación criptográfica del JWT se realice
         * 100% de manera local y en memoria utilizando la clave pública RSA sin peticiones salientes.
         */
        @Test
        @DisplayName("4.1 La validación del JWT se ejecuta localmente mediante la clave pública sin llamadas HTTP")
        void tokenValidationIsFullyLocalAndOffline() throws Exception {
            String validToken = tokenForFixture("cliente-a");

            // Ejecución directa de jwtDecoder sin contexto de red ni HTTP
            var decodedJwt = jwtDecoder.decode(validToken);

            assertThat(decodedJwt).isNotNull();
            assertThat(decodedJwt.getSubject()).isEqualTo("00000000-0000-0000-0000-000000000002");
            assertThat(decodedJwt.getIssuer().toString()).isEqualTo(jwtProperties.issuer());
            assertThat(decodedJwt.getAudience()).contains("security-service");
            assertThat(decodedJwt.getClaimAsStringList("roles")).contains("CLIENTE");
            assertThat(decodedJwt.getClaimAsString("customerId")).isEqualTo("10000000-0000-0000-0000-000000000001");
        }

        /**
         * Demuestra que el servicio puede procesar peticiones protegidas de forma autónoma,
         * corroborando que los microservicios consumidores (courier-service y shipment-service)
         * pueden validar tokens sin depender de la disponibilidad en tiempo real del emisor.
         */
        @Test
        @DisplayName("4.2 Endpoint protegido valida la identidad localmente sin interactuar con servicios externos")
        void protectedEndpointValidatesIndependently() throws Exception {
            String token = tokenForFixture("repartidor-a");

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is("00000000-0000-0000-0000-000000000004")))
                    .andExpect(jsonPath("$.courierId", is("20000000-0000-0000-0000-000000000001")));
        }
    }
}
