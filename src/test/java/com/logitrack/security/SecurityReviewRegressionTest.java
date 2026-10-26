package com.logitrack.security;

import com.logitrack.security.config.JwtProperties;
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
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class SecurityReviewRegressionTest {
    @Autowired MockMvc http;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired RsaKeyProvider keys;
    @Autowired JwtProperties properties;
    @Autowired JwtTokenService tokens;

    @ParameterizedTest
    @ValueSource(strings = {"exp", "iat", "subject", "roles", "kid", "audience"})
    void rejectsMalformedSignedContractAtBothEntryPoints(String scenario) throws Exception {
        var user = users.saveAndFlush(new User("review@example.test", encoder.encode("test-password"), Set.of(Role.ADMIN)));
        var claims = new JWTClaimsSet.Builder().subject(user.getId().toString()).issuer(properties.issuer())
                .audience(properties.audiences()).claim("roles", List.of("ADMIN"))
                .issueTime(Date.from(Instant.now())).expirationTime(Date.from(Instant.now().plusSeconds(600)));
        switch (scenario) {
            case "exp" -> claims.expirationTime(null);
            case "iat" -> claims.issueTime(null);
            case "subject" -> claims.subject("invalid-subject");
            case "roles" -> claims.claim("roles", List.of("ADMIN", "OWNER"));
            case "audience" -> claims.audience("shipment-service");
            default -> { }
        }
        var signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(scenario.equals("kid") ? "other-key" : keys.getKeyId()).build(), claims.build());
        signed.sign(new RSASSASigner(keys.getPrivateKey()));
        String token = signed.serialize();
        http.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token)).andExpect(status().isUnauthorized());
        assertThatThrownBy(() -> tokens.parseAndValidate(token)).isInstanceOf(IllegalArgumentException.class);
    }
}
