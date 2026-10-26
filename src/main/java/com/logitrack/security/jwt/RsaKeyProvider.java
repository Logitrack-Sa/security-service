package com.logitrack.security.jwt;

import com.logitrack.security.config.JwtProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

/**
 * Proveedor de claves criptográficas RSA para la firma y verificación de tokens JWT.
 *
 * <p>Soporta la carga segura de claves privadas desde archivos montados en formato PEM (PKCS#8)
 * mediante la propiedad de entorno {@code JWT_PRIVATE_KEY_LOCATION}. Solo el perfil test permite
 * generar un par efímero cuando no se configuró una clave. Una clave configurada inválida
 * o un par que no coincide impide el arranque en cualquier perfil.</p>
 *
 * <p>La clave privada nunca es expuesta a través de APIs de red. La clave pública se ofrece
 * a los microservicios consumidores a través de conjuntos de claves JWKS estándar (RFC 7517)
 * o en formato PEM para validaciones descentralizadas sin acoplamiento HTTP en tiempo de ejecución.</p>
 */
@Component
public class RsaKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyProvider.class);

    private final JwtProperties properties;
    private final ResourceLoader resourceLoader;
    private final org.springframework.core.env.Environment environment;

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private JWKSet publicJwkSet;
    private String publicKeyPem;

    /**
     * Construye el proveedor inyectando la configuración de JWT y el cargador de recursos.
     *
     * @param properties configuración de propiedades JWT.
     * @param resourceLoader cargador de recursos de Spring para resolver rutas de claves.
     * @param environment entorno que habilita claves efímeras exclusivamente para pruebas.
     */
    public RsaKeyProvider(JwtProperties properties, ResourceLoader resourceLoader, org.springframework.core.env.Environment environment) {
        this.properties = properties;
        this.resourceLoader = resourceLoader;
        this.environment = environment;
    }

    /**
     * Inicializa el par de claves RSA al arrancar el contexto de la aplicación.
     */
    @PostConstruct
    public void init() {
        KeyPair keyPair = loadOrGenerateKeyPair();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();

        RSAKey nimbusRsaKey = new RSAKey.Builder(this.publicKey)
                .keyID(properties.keyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();

        this.publicJwkSet = new JWKSet(nimbusRsaKey);
        this.publicKeyPem = encodePublicKeyToPem(this.publicKey);
    }

    private KeyPair loadOrGenerateKeyPair() {
        if (properties.privateKeyLocation() == null || properties.privateKeyLocation().isBlank()) {
            if (!environment.matchesProfiles("test")) {
                throw new IllegalStateException("JWT_PRIVATE_KEY_LOCATION es obligatoria fuera del perfil test");
            }
            try {
                var generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                return generator.generateKeyPair();
            } catch (GeneralSecurityException exception) {
                throw new IllegalStateException("No se pudo generar material RSA de test", exception);
            }
        }
        try {
            Resource source = resourceLoader.getResource(properties.privateKeyLocation());
            RSAPrivateKey privateKey = parsePrivateKeyFromPem(source.getContentAsString(StandardCharsets.UTF_8));
            RSAPublicKey publicKey;
            if (properties.publicKeyLocation() != null && !properties.publicKeyLocation().isBlank()) {
                publicKey = parsePublicKeyFromPem(resourceLoader.getResource(properties.publicKeyLocation())
                        .getContentAsString(StandardCharsets.UTF_8));
            } else if (privateKey instanceof RSAPrivateCrtKey crt) {
                publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
            } else {
                throw new IllegalStateException("Se requiere la clave pública correspondiente");
            }
            if (!privateKey.getModulus().equals(publicKey.getModulus()) || publicKey.getModulus().bitLength() < 2048) {
                throw new IllegalStateException("El par RSA debe coincidir y tener al menos 2048 bits");
            }
            return new KeyPair(publicKey, privateKey);
        } catch (IOException | GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalStateException("No se pudo cargar el material RSA configurado; no se sustituye por claves efímeras", exception);
        }
    }

    /**
     * Decodifica una clave privada RSA a partir de una cadena en formato PEM PKCS#8.
     *
     * @param pem contenido en texto plano del archivo PEM de clave privada.
     * @return instancia de {@link RSAPrivateKey}.
     * @throws GeneralSecurityException si el formato criptográfico es inválido.
     */
    public static RSAPrivateKey parsePrivateKeyFromPem(String pem) throws GeneralSecurityException {
        String clean = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(clean);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    /**
     * Decodifica una clave pública RSA a partir de una cadena en formato PEM X.509.
     *
     * @param pem contenido en texto plano del archivo PEM de clave pública.
     * @return instancia de {@link RSAPublicKey}.
     * @throws GeneralSecurityException si el formato criptográfico es inválido.
     */
    public static RSAPublicKey parsePublicKeyFromPem(String pem) throws GeneralSecurityException {
        String clean = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(clean);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    /**
     * Codifica una clave pública RSA en formato PEM estándar (X.509).
     *
     * @param publicKey clave pública a codificar.
     * @return representación en cadena PEM con encabezado y pie estándar.
     */
    public static String encodePublicKeyToPem(RSAPublicKey publicKey) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
    }

    /**
     * Obtiene la clave privada RSA utilizada para la firma de tokens.
     *
     * @return clave privada RSA.
     */
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Obtiene la clave pública RSA correspondiente.
     *
     * @return clave pública RSA.
     */
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Obtiene el identificador de clave {@code kid} configurado.
     *
     * @return identificador {@code kid}.
     */
    public String getKeyId() {
        return properties.keyId();
    }

    /**
     * Obtiene el conjunto de claves JWKS público (RFC 7517) para distribución a consumidores.
     *
     * @return conjunto de claves públicas JWK.
     */
    public JWKSet getPublicJwkSet() {
        return publicJwkSet;
    }

    /**
     * Obtiene la representación PEM de la clave pública RSA.
     *
     * @return clave pública en formato PEM.
     */
    public String getPublicKeyPem() {
        return publicKeyPem;
    }
}
