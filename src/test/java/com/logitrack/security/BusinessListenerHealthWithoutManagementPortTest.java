package com.logitrack.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "management.endpoints.web.exposure.include=health,info"
})
@ActiveProfiles("test")
class BusinessListenerHealthWithoutManagementPortTest {

    static final KeyPair KEYS;
    static final Path PRIVATE_KEY;
    static final Path PUBLIC_KEY;

    static {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KEYS = generator.generateKeyPair();
            PRIVATE_KEY = Files.createTempFile("security-test-private-", ".pem");
            PRIVATE_KEY.toFile().deleteOnExit();
            PUBLIC_KEY = Files.createTempFile("security-test-public-", ".pem");
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

    @Test
    void healthStaysAvailableAndTechnicalEndpointsRemainClosed() {
        var health = rest.getForEntity(url("/actuator/health"), String.class);
        assertThat(health.getStatusCode()).isEqualTo(HttpStatus.OK);
        var prometheus = rest.getForEntity(url("/actuator/prometheus"), String.class);
        assertThat(prometheus.getStatusCode().value()).isIn(401, 403, 404);
    }

    private String url(String path) {
        return "http://127.0.0.1:" + businessPort + path;
    }
}
