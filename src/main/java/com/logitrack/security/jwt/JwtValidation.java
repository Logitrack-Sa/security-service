package com.logitrack.security.jwt;

import com.logitrack.security.config.JwtProperties;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/** Un único contrato de validación para el filtro HTTP y el servicio de tokens. */
public final class JwtValidation {
    private static final Set<String> ROLES = Set.of("ADMIN", "CLIENTE", "REPARTIDOR");

    private JwtValidation() { }

    public static JwtDecoder decoder(RsaKeyProvider keys, JwtProperties properties) {
        var decoder = NimbusJwtDecoder.withPublicKey(keys.getPublicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer()),
                jwt -> validateContract(jwt, properties)));
        return decoder;
    }

    private static OAuth2TokenValidatorResult validateContract(Jwt jwt, JwtProperties properties) {
        try {
            UUID.fromString(jwt.getSubject());
            Object claim = jwt.getClaims().get("roles");
            boolean rolesValid = claim instanceof List<?> roles && !roles.isEmpty()
                    && roles.stream().allMatch(role -> role instanceof String && ROLES.contains(role));
            if (rolesValid && properties.keyId().equals(jwt.getHeaders().get("kid"))
                    && jwt.getAudience().contains("security-service") && jwt.getExpiresAt() != null
                    && jwt.getIssuedAt() != null && jwt.getIssuedAt().isBefore(jwt.getExpiresAt())
                    && !jwt.getIssuedAt().isAfter(Instant.now().plusSeconds(30))) {
                return OAuth2TokenValidatorResult.success();
            }
        } catch (RuntimeException ignored) {
            // Claims ausentes o de tipo incorrecto invalidan el contrato.
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "JWT fuera de contrato", null));
    }
}
