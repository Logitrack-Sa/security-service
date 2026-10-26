package com.logitrack.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.config.JwtProperties;
import com.logitrack.security.dto.CreateUserRequest;
import com.logitrack.security.dto.UpdateRolesRequest;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.jwt.JwtTokenService;
import com.logitrack.security.jwt.RsaKeyProvider;
import com.logitrack.security.repository.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Suite completa de pruebas para la issue S2-14:
 * Exponer perfil autenticado y proteger administración de usuarios.
 *
 * <p>Verifica:</p>
 * <ul>
 *   <li>Sin JWT válido responde 401 Unauthorized; perfil solo del sujeto autenticado, sin hashes ni claves.</li>
 *   <li>Rutas de provisión, roles y vínculos (/api/v1/users/**) exclusivas para ADMIN; rechazo 403 a CLIENTE/REPARTIDOR.</li>
 *   <li>Prohibición estricta de auto-modificación arbitraria de roles propios.</li>
 *   <li>Pruebas con tokens alterados, vencidos o con firmas ilegítimas.</li>
 *   <li>Autorización garantizada en el backend, independiente de parámetros enviados por el cliente.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AuthenticatedProfileAndAdminProtectionTest {

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

    @Nested
    @DisplayName("Criterio 1: Exposición de perfil autenticado (GET /api/v1/auth/me)")
    class AuthenticatedProfileTests {

        /**
         * Verifica que un usuario con rol CLIENTE obtenga su propio perfil sin exponer hashes ni contraseñas.
         */
        @Test
        @DisplayName("GET /api/v1/auth/me con token de CLIENTE devuelve exclusivamente su perfil sin secretos")
        void getProfileWithClienteToken() throws Exception {
            var customerId = UUID.randomUUID();
            var user = new User("cliente.me@logitrack.com", "cliente_me", "Cliente Perfil",
                    passwordEncoder.encode("PasswordSeguro123!"), Set.of(Role.CLIENTE), customerId, null);
            userRepository.saveAndFlush(user);

            String token = jwtTokenService.generateToken(user);

            var result = http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(user.getId().toString())))
                    .andExpect(jsonPath("$.email", is("cliente.me@logitrack.com")))
                    .andExpect(jsonPath("$.username", is("cliente_me")))
                    .andExpect(jsonPath("$.name", is("Cliente Perfil")))
                    .andExpect(jsonPath("$.roles", hasItem("CLIENTE")))
                    .andExpect(jsonPath("$.roles.length()", is(1)))
                    .andExpect(jsonPath("$.customerId", is(customerId.toString())))
                    .andExpect(jsonPath("$.courierId").doesNotExist())
                    .andExpect(jsonPath("$.password").doesNotExist())
                    .andExpect(jsonPath("$.passwordHash").doesNotExist())
                    .andReturn();

            String body = result.getResponse().getContentAsString();
            assertThat(body).doesNotContain("password").doesNotContain("PasswordSeguro123!").doesNotContain("$2a$");
        }

        /**
         * Verifica que un usuario con rol REPARTIDOR obtenga su propio perfil con su courierId.
         */
        @Test
        @DisplayName("GET /api/v1/auth/me con token de REPARTIDOR devuelve courierId vinculado")
        void getProfileWithRepartidorToken() throws Exception {
            var courierId = UUID.randomUUID();
            var courierUser = new User("courier.me@logitrack.com", "courier_me", "Courier Perfil",
                    passwordEncoder.encode("Password123!"), Set.of(Role.REPARTIDOR), null, courierId);
            userRepository.saveAndFlush(courierUser);

            String token = jwtTokenService.generateToken(courierUser);

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(courierUser.getId().toString())))
                    .andExpect(jsonPath("$.email", is("courier.me@logitrack.com")))
                    .andExpect(jsonPath("$.roles", hasItem("REPARTIDOR")))
                    .andExpect(jsonPath("$.courierId", is(courierId.toString())));
        }

        /**
         * Verifica que un usuario con rol ADMIN obtenga su propio perfil.
         */
        @Test
        @DisplayName("GET /api/v1/auth/me con token de ADMIN devuelve su perfil correspondiente")
        void getProfileWithAdminToken() throws Exception {
            var adminUser = new User("admin.me@logitrack.com", "admin_me", "Admin Perfil",
                    passwordEncoder.encode("Password123!"), Set.of(Role.ADMIN), null, null);
            userRepository.saveAndFlush(adminUser);

            String token = jwtTokenService.generateToken(adminUser);

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(adminUser.getId().toString())))
                    .andExpect(jsonPath("$.email", is("admin.me@logitrack.com")))
                    .andExpect(jsonPath("$.roles", hasItem("ADMIN")));
        }

        /**
         * Verifica que solicitar GET /api/v1/auth/me sin cabecera Authorization responda 401 Unauthorized.
         */
        @Test
        @DisplayName("GET /api/v1/auth/me sin token responde 401 Unauthorized")
        void getProfileWithoutTokenReturns401() throws Exception {
            http.perform(get("/api/v1/auth/me"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")))
                    .andExpect(jsonPath("$.status", is(401)))
                    .andExpect(jsonPath("$.message", containsString("Token JWT ausente")));
        }

        /**
         * Verifica que solicitar GET /api/v1/auth/me con un token de usuario deshabilitado responda 401.
         */
        @Test
        @DisplayName("GET /api/v1/auth/me con cuenta de usuario deshabilitada responde 401")
        void getProfileWithDisabledUserReturns401() throws Exception {
            var user = new User("disabled.me@logitrack.com", "disabled_me", "Disabled",
                    passwordEncoder.encode("Password123!"), Set.of(Role.CLIENTE), null, null);
            user.setEnabled(false);
            userRepository.saveAndFlush(user);

            String token = jwtTokenService.generateToken(user);

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }
    }

    @Nested
    @DisplayName("Criterio 2: Validación de tokens alterados, firma externa y expirados")
    class TamperedAndInvalidTokenTests {

        /**
         * Verifica que un token cuya firma haya sido alterada sea rechazado con 401.
         */
        @Test
        @DisplayName("Token con firma alterada responde 401 Unauthorized en GET /api/v1/auth/me")
        void tamperedTokenReturns401() throws Exception {
            var user = new User("user.tamper@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
            userRepository.saveAndFlush(user);

            String validToken = jwtTokenService.generateToken(user);
            String[] parts = validToken.split("\\.");
            String forgedSignature = parts[2].substring(0, parts[2].length() - 4) + "XXXX";
            String tamperedToken = parts[0] + "." + parts[1] + "." + forgedSignature;

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tamperedToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }

        /**
         * Verifica que un token firmado por otra clave privada no reconocida sea rechazado con 401.
         */
        @Test
        @DisplayName("Token firmado con clave privada externa o no confiable responde 401")
        void foreignKeySignedTokenReturns401() throws Exception {
            var user = new User("user.foreign@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
            userRepository.saveAndFlush(user);

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair foreignKey = generator.generateKeyPair();

            Instant now = Instant.now();
            var claims = new JWTClaimsSet.Builder()
                    .subject(user.getId().toString())
                    .issuer(jwtProperties.issuer())
                    .audience(jwtProperties.audiences())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(3600)))
                    .claim("roles", List.of("CLIENTE"))
                    .build();

            var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("foreign-kid").build(), claims);
            jwt.sign(new RSASSASigner((RSAPrivateKey) foreignKey.getPrivate()));
            String foreignToken = jwt.serialize();

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + foreignToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }

        /**
         * Verifica que un token con fecha de expiración vencida sea rechazado con 401.
         */
        @Test
        @DisplayName("Token con fecha de expiración vencida responde 401")
        void expiredTokenReturns401() throws Exception {
            var user = new User("user.expired@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
            userRepository.saveAndFlush(user);

            Instant past = Instant.now().minusSeconds(3600);
            var claims = new JWTClaimsSet.Builder()
                    .subject(user.getId().toString())
                    .issuer(jwtProperties.issuer())
                    .audience(jwtProperties.audiences())
                    .issueTime(Date.from(past.minusSeconds(3600)))
                    .expirationTime(Date.from(past))
                    .claim("roles", List.of("CLIENTE"))
                    .build();

            var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwtProperties.keyId()).build(), claims);
            jwt.sign(new RSASSASigner(rsaKeyProvider.getPrivateKey()));
            String expiredToken = jwt.serialize();

            http.perform(get("/api/v1/auth/me")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")));
        }
    }

    @Nested
    @DisplayName("Criterio 3: Protección de operaciones administrativas y rechazo de auto-modificación de roles")
    class AdminProtectionAndRoleModificationTests {

        /**
         * Verifica que un usuario con rol CLIENTE reciba 403 Forbidden al intentar acceder a rutas de administración.
         */
        @Test
        @DisplayName("Usuario con rol CLIENTE recibe 403 Forbidden al intentar crear usuarios en POST /api/v1/users")
        void clienteForbiddenToCreateUsers() throws Exception {
            var cliente = new User("cliente.forbidden@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
            userRepository.saveAndFlush(cliente);
            String clientToken = jwtTokenService.generateToken(cliente);

            var request = new CreateUserRequest("nuevo@logitrack.com", "Pass123!", "nuevo_user", "Nuevo", Set.of(Role.CLIENTE), null, null);

            http.perform(post("/api/v1/users")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + clientToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code", is("FORBIDDEN")))
                    .andExpect(jsonPath("$.status", is(403)))
                    .andExpect(jsonPath("$.message", containsString("permisos insuficientes")));
        }

        /**
         * Verifica que un usuario con rol REPARTIDOR reciba 403 Forbidden al intentar consultar usuarios.
         */
        @Test
        @DisplayName("Usuario con rol REPARTIDOR recibe 403 Forbidden en GET /api/v1/users/{id}")
        void repartidorForbiddenToAccessUsers() throws Exception {
            var courier = new User("repartidor.forbidden@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.REPARTIDOR));
            userRepository.saveAndFlush(courier);
            String courierToken = jwtTokenService.generateToken(courier);

            http.perform(get("/api/v1/users/" + courier.getId())
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + courierToken))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code", is("FORBIDDEN")));
        }

        /**
         * Verifica que un usuario con rol ADMIN pueda crear usuarios y gestionar identidades.
         */
        @Test
        @DisplayName("Usuario con rol ADMIN accede exitosamente a POST /api/v1/users")
        void adminCanCreateUserSuccessfully() throws Exception {
            var admin = new User("admin.auth@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.ADMIN));
            userRepository.saveAndFlush(admin);
            String adminToken = jwtTokenService.generateToken(admin);

            var request = new CreateUserRequest("empleado@logitrack.com", "Pass123!", "empleado_admin", "Empleado", Set.of(Role.CLIENTE), null, null);

            http.perform(post("/api/v1/users")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id", notNullValue()))
                    .andExpect(jsonPath("$.email", is("empleado@logitrack.com")));
        }

        /**
         * Verifica que un usuario ADMIN no pueda auto-modificar arbitrariamente sus propios roles.
         */
        @Test
        @DisplayName("Intento de auto-modificación arbitraria de roles propios es rechazado con 400 Bad Request")
        void selfRoleModificationIsProhibited() throws Exception {
            var admin = new User("admin.self@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.ADMIN));
            userRepository.saveAndFlush(admin);
            String adminToken = jwtTokenService.generateToken(admin);

            var updateRolesRequest = new UpdateRolesRequest(Set.of(Role.CLIENTE));

            http.perform(put("/api/v1/users/" + admin.getId() + "/roles")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(updateRolesRequest)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("PRIVILEGE_ESCALATION")))
                    .andExpect(jsonPath("$.message", containsString("auto-modificación arbitraria de roles propios")));
        }

        /**
         * Verifica que un ADMIN pueda actualizar los roles de otro usuario distinto.
         */
        @Test
        @DisplayName("ADMIN puede actualizar roles de otro usuario que no sea él mismo")
        void adminCanUpdateOtherUserRoles() throws Exception {
            var admin = new User("admin.actor@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.ADMIN));
            userRepository.saveAndFlush(admin);
            String adminToken = jwtTokenService.generateToken(admin);

            var targetUser = new User("target.user@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
            userRepository.saveAndFlush(targetUser);

            var updateRolesRequest = new UpdateRolesRequest(Set.of(Role.CLIENTE, Role.REPARTIDOR));

            http.perform(put("/api/v1/users/" + targetUser.getId() + "/roles")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(updateRolesRequest)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.roles", hasItem("CLIENTE")))
                    .andExpect(jsonPath("$.roles", hasItem("REPARTIDOR")));
        }
    }
}
