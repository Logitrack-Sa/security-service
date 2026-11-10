package com.logitrack.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "management.server.port=0",
        "management.server.address=127.0.0.1",
        "management.endpoints.web.exposure.include=health,info,prometheus",
        "management.endpoint.prometheus.enabled=true",
        "management.prometheus.metrics.export.enabled=true",
        "management.metrics.tags.application=security-service",
        "management.metrics.distribution.percentiles-histogram.http.server.requests=true"
})
@ActiveProfiles("test")
class ManagementListenerSeparationTest {

    static final KeyPair KEYS;
    static final Path PRIVATE_KEY;
    static final Path PUBLIC_KEY;

    static {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KEYS = generator.generateKeyPair();
            PRIVATE_KEY = Files.createTempFile("security-mgmt-private-", ".pem");
            PRIVATE_KEY.toFile().deleteOnExit();
            PUBLIC_KEY = Files.createTempFile("security-mgmt-public-", ".pem");
            PUBLIC_KEY.toFile().deleteOnExit();
            Files.writeString(PRIVATE_KEY, "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(KEYS.getPrivate().getEncoded())
                    + "\n-----END PRIVATE KEY-----\n");
            Files.writeString(PUBLIC_KEY, "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(KEYS.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n");
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    @DynamicPropertySource
    static void jwtProperties(DynamicPropertyRegistry registry) {
        registry.add("logitrack.security.jwt.private-key-location", () -> PRIVATE_KEY.toUri().toString());
        registry.add("logitrack.security.jwt.public-key-location", () -> PUBLIC_KEY.toUri().toString());
        registry.add("logitrack.security.jwt.key-id", () -> "test-ephemeral");
        registry.add("logitrack.security.jwt.issuer", () -> "https://issuer.test");
        registry.add("logitrack.security.jwt.audiences", () -> "security-service,courier-service,shipment-service");
    }

    @LocalServerPort
    int businessPort;

    @Autowired
    TestRestTemplate rest;

    @Autowired
    Environment environment;

    @Test
    void managementListenerExposesPrometheusWithApplicationTag() {
        var response = rest.getForEntity(url(managementPort(), "/actuator/prometheus"), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("application=\"security-service\"");
    }

    @Test
    void managementListenerExposesHealth() {
        var response = rest.getForEntity(url(managementPort(), "/actuator/health"), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void trafficGeneratesHttpPercentilesBuckets() {
        // Tráfico al listener de negocio
        rest.getForEntity(url(businessPort, "/api/v1/auth/public-key"), String.class);

        // Tráfico al listener de gestión
        rest.getForEntity(url(managementPort(), "/actuator/health"), String.class);

        var response = rest.getForEntity(url(managementPort(), "/actuator/prometheus"), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("http_server_requests_seconds_bucket{");
        assertThat(response.getBody()).contains("le=");
        assertThat(response.getBody()).contains("http_server_requests_seconds_count");
    }

    @Test
    void businessListenerDoesNotExposePrometheusOrInfo() {
        for (String path : new String[] { "/actuator/prometheus", "/actuator/info" }) {
            var response = rest.getForEntity(url(businessPort, path), String.class);
            assertThat(response.getStatusCode().value()).isIn(401, 403, 404);
        }
    }

    @Test
    void businessListenerRejectsTechnicalEndpointsEvenWithValidJwt() throws Exception {
        var headers = new HttpHeaders();
        headers.setBearerAuth(validToken());
        for (String path : new String[] { "/actuator/prometheus", "/actuator/info" }) {
            var response = rest.exchange(url(businessPort, path), HttpMethod.GET, new HttpEntity<>(headers), String.class);
            assertThat(response.getStatusCode().value()).isIn(401, 403, 404);
        }
    }

    @Test
    void administrativeEndpointsAreNotExposed() {
        for (String path : new String[] { "/actuator/env", "/actuator/beans", "/actuator/threaddump" }) {
            for (int port : new int[] { businessPort, managementPort() }) {
                var response = rest.getForEntity(url(port, path), String.class);
                assertThat(response.getStatusCode().value()).isIn(401, 403, 404, 405);
            }
        }
        // POST /actuator/shutdown debe ser rechazado en ambos listeners
        for (int port : new int[] { businessPort, managementPort() }) {
            var postResponse = rest.postForEntity(url(port, "/actuator/shutdown"), null, String.class);
            assertThat(postResponse.getStatusCode().value()).isIn(401, 403, 404, 405);
        }
    }

    private String validToken() throws Exception {
        var claims = new JWTClaimsSet.Builder()
                .subject(UUID.randomUUID().toString())
                .issuer("https://issuer.test")
                .audience(List.of("security-service"))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("roles", List.of("ADMIN"))
                .build();
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-ephemeral").build(), claims);
        jwt.sign(new RSASSASigner((RSAPrivateKey) KEYS.getPrivate()));
        return jwt.serialize();
    }

    private int managementPort() {
        return Integer.parseInt(environment.getRequiredProperty("local.management.port"));
    }

    private String url(int port, String path) {
        return "http://127.0.0.1:" + port + path;
    }
}
