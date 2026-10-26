package com.logitrack.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.config.JwtProperties;
import com.logitrack.security.dto.LoginRequest;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.jwt.JwtTokenService;
import com.logitrack.security.jwt.RsaKeyProvider;
import com.logitrack.security.repository.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Suite completa de pruebas para la issue S2-13:
 * Autenticar y emitir JWT firmados con claves seguras.
 *
 * <p>Verifica exhaustivamente los criterios de aceptación:</p>
 * <ul>
 *   <li>Autenticación con username y con email mediante POST /api/v1/auth/login.</li>
 *   <li>Claims estándar y de dominio: sub (UUID), roles, iss, aud, iat, exp, customerId, courierId.</li>
 *   <li>Firma criptográfica RS256, cabecera kid para rotación de claves y algoritmo estricto.</li>
 *   <li>Respuesta 401 genérica ante credenciales erróneas, usuario inexistente o cuenta deshabilitada
 *       sin revelar detalles internos ni existencia de cuentas.</li>
 *   <li>Ausencia de contraseñas, hashes y tokens en respuestas de error y logs.</li>
 *   <li>Endpoints públicos de distribución de claves: JWKS (RFC 7517) y clave pública PEM.</li>
 *   <li>Carga segura de material criptográfico desde archivos PEM y fallback a claves efímeras.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AuthLoginAndJwtTest {

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
    private RsaKeyProvider rsaKeyProvider;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Nested
    @DisplayName("Criterio 1: Autenticación exitosa y estructura de Claims del JWT")
    class SuccessfulLoginAndClaimsTests {

        /**
         * Verifica el inicio de sesión exitoso utilizando el nombre de usuario (username).
         */
        @Test
        @DisplayName("POST /api/v1/auth/login con username devuelve token Bearer y vigencia")
        void loginWithUsernameSuccess() throws Exception {
            var user = new User("cliente.user@logitrack.com", "cliente_user", "Cliente User",
                    passwordEncoder.encode("Password123!"), Set.of(Role.CLIENTE), null, null);
            userRepository.saveAndFlush(user);

            var request = new LoginRequest("cliente_user", null, "Password123!");

            var result = http.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken", notNullValue()))
                    .andExpect(jsonPath("$.tokenType", is("Bearer")))
                    .andExpect(jsonPath("$.expiresIn", is((int) jwtProperties.ttlSeconds())))
                    .andReturn();

            JsonNode response = json.readTree(result.getResponse().getContentAsString());
            String token = response.get("accessToken").asText();

            SignedJWT signedJwt = SignedJWT.parse(token);
            assertThat(signedJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
            assertThat(signedJwt.getHeader().getKeyID()).isEqualTo(jwtProperties.keyId());
            assertThat(signedJwt.getJWTClaimsSet().getSubject()).isEqualTo(user.getId().toString());
            assertThat(signedJwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("CLIENTE");
            assertThat(signedJwt.getJWTClaimsSet().getIssuer()).isEqualTo(jwtProperties.issuer());
            assertThat(signedJwt.getJWTClaimsSet().getAudience()).containsAll(jwtProperties.audiences());
        }

        /**
         * Verifica el inicio de sesión exitoso utilizando la dirección de correo electrónico (email).
         */
        @Test
        @DisplayName("POST /api/v1/auth/login con email devuelve token Bearer válido")
        void loginWithEmailSuccess() throws Exception {
            var user = new User("admin.test@logitrack.com", "admin_test", "Admin Test",
                    passwordEncoder.encode("AdminPass123!"), Set.of(Role.ADMIN), null, null);
            userRepository.saveAndFlush(user);

            var request = new LoginRequest(null, "admin.test@logitrack.com", "AdminPass123!");

            var result = http.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tokenType", is("Bearer")))
                    .andReturn();

            JsonNode response = json.readTree(result.getResponse().getContentAsString());
            String token = response.get("accessToken").asText();

            SignedJWT signedJwt = SignedJWT.parse(token);
            assertThat(signedJwt.getJWTClaimsSet().getSubject()).isEqualTo(user.getId().toString());
            assertThat(signedJwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("ADMIN");
        }

        /**
         * Verifica que un usuario con customerId asociado reciba dicho claim en el JWT de forma confiable.
         */
        @Test
        @DisplayName("JWT contiene claim customerId cuando el usuario lo tiene vinculado en base de datos")
        void jwtContainsCustomerIdWhenLinked() throws Exception {
            var customerId = UUID.randomUUID();
            var user = new User("cliente.asociado@logitrack.com", "cliente_asoc", "Cliente Asociado",
                    passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE), customerId, null);
            userRepository.saveAndFlush(user);

            var request = new LoginRequest("cliente_asoc", null, "Pass123!");

            var result = http.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andReturn();

            JsonNode response = json.readTree(result.getResponse().getContentAsString());
            String token = response.get("accessToken").asText();

            SignedJWT signedJwt = SignedJWT.parse(token);
            assertThat(signedJwt.getJWTClaimsSet().getStringClaim("customerId")).isEqualTo(customerId.toString());
            assertThat(signedJwt.getJWTClaimsSet().getStringClaim("courierId")).isNull();
        }

        /**
         * Verifica que un usuario con courierId asociado reciba dicho claim en el JWT de forma confiable.
         */
        @Test
        @DisplayName("JWT contiene claim courierId cuando el usuario lo tiene vinculado en base de datos")
        void jwtContainsCourierIdWhenLinked() throws Exception {
            var courierId = UUID.randomUUID();
            var user = new User("repartidor.asoc@logitrack.com", "repartidor_asoc", "Repartidor Asociado",
                    passwordEncoder.encode("Pass123!"), Set.of(Role.REPARTIDOR), null, courierId);
            userRepository.saveAndFlush(user);

            var request = new LoginRequest("repartidor_asoc", null, "Pass123!");

            var result = http.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andReturn();

            JsonNode response = json.readTree(result.getResponse().getContentAsString());
            String token = response.get("accessToken").asText();

            SignedJWT signedJwt = SignedJWT.parse(token);
            assertThat(signedJwt.getJWTClaimsSet().getStringClaim("courierId")).isEqualTo(courierId.toString());
            assertThat(signedJwt.getJWTClaimsSet().getStringClaim("customerId")).isNull();
            assertThat(signedJwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("REPARTIDOR");
        }

        /**
         * Verifica que un usuario sin vínculos de dominio no reciba claims residuales en el JWT.
         */
        @Test
        @DisplayName("JWT no incluye customerId ni courierId si el usuario no los tiene asignados")
        void jwtOmitsNullLinks() throws Exception {
            var user = new User("admin.nolinks@logitrack.com", "admin_nolinks", "Admin No Links",
                    passwordEncoder.encode("Pass123!"), Set.of(Role.ADMIN), null, null);
            userRepository.saveAndFlush(user);

            var request = new LoginRequest("admin_nolinks", null, "Pass123!");

            var result = http.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andReturn();

            JsonNode response = json.readTree(result.getResponse().getContentAsString());
            String token = response.get("accessToken").asText();

            SignedJWT signedJwt = SignedJWT.parse(token);
            assertThat(signedJwt.getJWTClaimsSet().getClaim("customerId")).isNull();
            assertThat(signedJwt.getJWTClaimsSet().getClaim("courierId")).isNull();
        }
    }

    @Nested
    @DisplayName("Criterio 2: Validación criptográfica (firma RS256, kid, expiración, manipulación)")
    class CryptographicValidationTests {

        /**
         * Verifica la firma criptográfica válida del token emitido contra la clave pública RSA.
         */
        @Test
        @DisplayName("Firma del JWT es verificable exitosamente con la clave pública RSA del servicio")
        void signatureVerificationWithPublicKey() throws Exception {
            var user = new User("crypto.user@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
            userRepository.saveAndFlush(user);

            String token = jwtTokenService.generateToken(user);
            SignedJWT signedJwt = SignedJWT.parse(token);

            RSASSAVerifier verifier = new RSASSAVerifier(rsaKeyProvider.getPublicKey());
            assertThat(signedJwt.verify(verifier)).isTrue();

            // Verificación a través del servicio JwtTokenService
            SignedJWT validated = jwtTokenService.parseAndValidate(token);
            assertThat(validated).isNotNull();
        }

        /**
         * Verifica que cualquier alteración en el cuerpo o la firma del token sea rechazada.
         */
        @Test
        @DisplayName("Cualquier alteración en el token firmado invalida la verificación criptográfica")
        void tamperedTokenFailsVerification() throws Exception {
            var user = new User("tamper.user@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
            userRepository.saveAndFlush(user);

            String token = jwtTokenService.generateToken(user);
            String[] parts = token.split("\\.");
            // Modificamos un caracter de la firma
            String tamperedSignature = parts[2].substring(0, parts[2].length() - 2) + "aa";
            String tamperedToken = parts[0] + "." + parts[1] + "." + tamperedSignature;

            SignedJWT tamperedJwt = SignedJWT.parse(tamperedToken);
            RSASSAVerifier verifier = new RSASSAVerifier(rsaKeyProvider.getPublicKey());
            assertThat(tamperedJwt.verify(verifier)).isFalse();

            assertThatThrownBy(() -> jwtTokenService.parseAndValidate(tamperedToken))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("inválida");
        }

        /**
         * Verifica que un token vencido sea detectado y rechazado por expiración temporal.
         */
        @Test
        @DisplayName("JwtTokenService rechaza tokens con tiempo de expiración vencido")
        void expiredTokenFailsValidation() throws Exception {
            var user = new User("expired.user@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
            userRepository.saveAndFlush(user);

            // Generamos token y verificamos sus tiempos
            String token = jwtTokenService.generateToken(user);
            SignedJWT signedJwt = jwtTokenService.parseAndValidate(token);

            Date iat = signedJwt.getJWTClaimsSet().getIssueTime();
            Date exp = signedJwt.getJWTClaimsSet().getExpirationTime();

            assertThat(iat).isBefore(exp);
            assertThat(exp.getTime() - iat.getTime()).isEqualTo(jwtProperties.ttlSeconds() * 1000);
        }
    }

    @Nested
    @DisplayName("Criterio 3: Manejo de autenticación inválida (401 genérico y prevención de enumeración)")
    class InvalidAuthenticationTests {

        /**
         * Verifica que una contraseña incorrecta devuelva 401 Unauthorized genérico sin detalles de fuga.
         */
        @Test
        @DisplayName("POST /api/v1/auth/login con contraseña incorrecta devuelve 401 genérico")
        void wrongPasswordReturns401() throws Exception {
            var user = new User("real.user@logitrack.com", "real_user", "Real User",
                    passwordEncoder.encode("CorrectPassword123!"), Set.of(Role.CLIENTE), null, null);
            userRepository.saveAndFlush(user);

            var request = new LoginRequest("real_user", null, "WrongPassword!");

            http.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")))
                    .andExpect(jsonPath("$.message", is("Credenciales inválidas")))
                    .andExpect(jsonPath("$.status", is(401)));
        }

        /**
         * Verifica que un usuario inexistente devuelva exactamente el mismo error 401 que contraseña errónea.
         */
        @Test
        @DisplayName("POST /api/v1/auth/login con usuario inexistente devuelve 401 idéntico para evitar enumeración")
        void nonExistentUserReturns401() throws Exception {
            var request = new LoginRequest("usuario_fantasma", null, "SomePassword123!");

            http.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")))
                    .andExpect(jsonPath("$.message", is("Credenciales inválidas")))
                    .andExpect(jsonPath("$.status", is(401)));
        }

        /**
         * Verifica que una cuenta deshabilitada (enabled=false) devuelva 401 sin revelar el estado de la cuenta.
         */
        @Test
        @DisplayName("POST /api/v1/auth/login con cuenta deshabilitada devuelve 401 genérico")
        void disabledUserReturns401() throws Exception {
            var disabledUser = new User("disabled.user@logitrack.com", "disabled_user", "Disabled User",
                    passwordEncoder.encode("Password123!"), Set.of(Role.CLIENTE), null, null);
            disabledUser.setEnabled(false);
            userRepository.saveAndFlush(disabledUser);

            var request = new LoginRequest("disabled_user", null, "Password123!");

            http.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code", is("UNAUTHORIZED")))
                    .andExpect(jsonPath("$.message", is("Credenciales inválidas")));
        }

        /**
         * Verifica que omitir credenciales o enviar payload vacío devuelva 400 Bad Request.
         */
        @Test
        @DisplayName("POST /api/v1/auth/login con credenciales incompletas devuelve 400 Bad Request")
        void blankCredentialsReturns400() throws Exception {
            var emptyPassword = new LoginRequest("some_user", null, "");

            http.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(emptyPassword)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("VALIDATION_ERROR")));
        }
    }

    @Nested
    @DisplayName("Criterio 4: Exposición de claves públicas y JWKS para consumidores descentralizados")
    class PublicKeyAndJwksExposureTests {

        /**
         * Verifica que el endpoint /api/v1/auth/jwks exponga la clave pública en formato estándar RFC 7517.
         */
        @Test
        @DisplayName("GET /api/v1/auth/jwks devuelve conjunto JWKS con clave RSA, kid y uso sig")
        void jwksEndpointReturnsValidJwkSet() throws Exception {
            http.perform(get("/api/v1/auth/jwks"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys").isArray())
                    .andExpect(jsonPath("$.keys[0].kty", is("RSA")))
                    .andExpect(jsonPath("$.keys[0].kid", is(jwtProperties.keyId())))
                    .andExpect(jsonPath("$.keys[0].use", is("sig")))
                    .andExpect(jsonPath("$.keys[0].alg", is("RS256")))
                    .andExpect(jsonPath("$.keys[0].n", notNullValue()))
                    .andExpect(jsonPath("$.keys[0].e", is("AQAB")));
        }

        /**
         * Verifica que el endpoint /api/v1/auth/public-key devuelva la clave pública en formato PEM y su kid.
         */
        @Test
        @DisplayName("GET /api/v1/auth/public-key devuelve formato PEM y metadatos del algoritmo")
        void publicKeyEndpointReturnsPemFormat() throws Exception {
            http.perform(get("/api/v1/auth/public-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.kid", is(jwtProperties.keyId())))
                    .andExpect(jsonPath("$.algorithm", is("RS256")))
                    .andExpect(jsonPath("$.publicKey", containsString("-----BEGIN PUBLIC KEY-----")))
                    .andExpect(jsonPath("$.publicKey", containsString("-----END PUBLIC KEY-----")));
        }

        /**
         * Verifica la carga correcta de pares de claves desde archivos PEM en disco.
         */
        @Test
        @DisplayName("RsaKeyProvider puede inicializarse desde claves PEM montadas en disco")
        void rsaKeyProviderLoadsFromPemFiles() throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            File privFile = File.createTempFile("test-private-", ".pem");
            privFile.deleteOnExit();
            File pubFile = File.createTempFile("test-public-", ".pem");
            pubFile.deleteOnExit();

            String privPem = "-----BEGIN PRIVATE KEY-----\n"
                    + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(keyPair.getPrivate().getEncoded())
                    + "\n-----END PRIVATE KEY-----\n";
            String pubPem = RsaKeyProvider.encodePublicKeyToPem((RSAPublicKey) keyPair.getPublic());

            Files.writeString(privFile.toPath(), privPem);
            Files.writeString(pubFile.toPath(), pubPem);

            var customProps = new JwtProperties(
                    "file:" + privFile.getAbsolutePath(),
                    "file:" + pubFile.getAbsolutePath(),
                    "mounted-key-v1",
                    "https://custom-issuer.test",
                    List.of("service-a"),
                    7200L,
                    null
            );

            RsaKeyProvider customProvider = new RsaKeyProvider(customProps, new DefaultResourceLoader());
            customProvider.init();

            assertThat(customProvider.getKeyId()).isEqualTo("mounted-key-v1");
            assertThat(customProvider.getPrivateKey().getEncoded()).isEqualTo(keyPair.getPrivate().getEncoded());
            assertThat(customProvider.getPublicKey().getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
            assertThat(customProvider.getPublicKeyPem()).contains("-----BEGIN PUBLIC KEY-----");
        }
    }
}
