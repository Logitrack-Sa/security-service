package com.logitrack.security.jwt;

import com.logitrack.security.config.JwtProperties;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Servicio encargado de la emisión, firma digital y verificación de tokens JWT según el contrato del Sprint 2.
 *
 * <p>Genera tokens conformes al estándar con el algoritmo {@code RS256}, incluyendo cabecera {@code kid}
 * y claims estándar y de dominio:</p>
 * <ul>
 *   <li>{@code sub}: UUID del usuario emisor como cadena.</li>
 *   <li>{@code roles}: Lista de nombres de roles ({@code ADMIN}, {@code CLIENTE}, {@code REPARTIDOR}).</li>
 *   <li>{@code iss}: Emisor configurado en las propiedades del servicio.</li>
 *   <li>{@code aud}: Lista de audiencias válidas para los microservicios del ecosistema.</li>
 *   <li>{@code iat}: Momento de emisión en tiempo UTC.</li>
 *   <li>{@code exp}: Momento de expiración según la duración configurable {@code ttlSeconds}.</li>
 *   <li>{@code customerId}: Identificador UUID de dominio de cliente asociado en base de datos (si existe).</li>
 *   <li>{@code courierId}: Identificador UUID de dominio de repartidor asociado en base de datos (si existe).</li>
 * </ul>
 */
@Service
public class JwtTokenService {

    private final RsaKeyProvider keyProvider;
    private final JwtProperties properties;

    /**
     * Construye el servicio de tokens JWT.
     *
     * @param keyProvider proveedor de claves criptográficas RSA.
     * @param properties propiedades de configuración de JWT.
     */
    public JwtTokenService(RsaKeyProvider keyProvider, JwtProperties properties) {
        this.keyProvider = keyProvider;
        this.properties = properties;
    }

    /**
     * Emite un token JWT firmado criptográficamente con RS256 para el usuario autenticado.
     *
     * <p>Los claims de identidad y vínculos de dominio se obtienen exclusivamente del estado
     * persistido y verificado del usuario, nunca de parámetros suministrados por el cliente.</p>
     *
     * @param user entidad de usuario persistida y validada.
     * @return cadena compacta serializada del JWT firmado.
     */
    public String generateToken(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(properties.ttlSeconds());

        List<String> roleNames = user.getRoles().stream()
                .map(Role::name)
                .toList();

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(user.getId().toString())
                .issuer(properties.issuer())
                .audience(properties.audiences())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .claim("roles", roleNames);

        if (user.getCustomerId() != null) {
            claimsBuilder.claim("customerId", user.getCustomerId().toString());
        }
        if (user.getCourierId() != null) {
            claimsBuilder.claim("courierId", user.getCourierId().toString());
        }

        JWTClaimsSet claimsSet = claimsBuilder.build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(keyProvider.getKeyId())
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJwt = new SignedJWT(header, claimsSet);

        try {
            RSASSASigner signer = new RSASSASigner(keyProvider.getPrivateKey());
            signedJwt.sign(signer);
            return signedJwt.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Error al firmar criptográficamente el token JWT", ex);
        }
    }

    /**
     * Analiza y verifica la firma y validez temporal de un token JWT recibido.
     *
     * @param token cadena serializada del JWT.
     * @return token analizado {@link SignedJWT} si la firma y estructura son válidas.
     * @throws IllegalArgumentException si el token es nulo, corrupto, manipulado o expirado.
     */
    public SignedJWT parseAndValidate(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("El token JWT no puede ser nulo o vacío");
        }
        try {
            SignedJWT signedJwt = SignedJWT.parse(token);

            if (!JWSAlgorithm.RS256.equals(signedJwt.getHeader().getAlgorithm())) {
                throw new IllegalArgumentException("Algoritmo no permitido: " + signedJwt.getHeader().getAlgorithm());
            }

            RSASSAVerifier verifier = new RSASSAVerifier(keyProvider.getPublicKey());
            if (!signedJwt.verify(verifier)) {
                throw new IllegalArgumentException("Firma criptográfica inválida");
            }

            Date expirationTime = signedJwt.getJWTClaimsSet().getExpirationTime();
            if (expirationTime != null && expirationTime.before(new Date())) {
                throw new IllegalArgumentException("El token JWT ha expirado");
            }

            return signedJwt;
        } catch (ParseException | JOSEException ex) {
            throw new IllegalArgumentException("Token JWT con formato o firma inválida: " + ex.getMessage(), ex);
        }
    }

    /**
     * Obtiene el tiempo de vida en segundos configurado para los tokens emitidos.
     *
     * @return duración en segundos.
     */
    public long getTtlSeconds() {
        return properties.ttlSeconds();
    }
}
