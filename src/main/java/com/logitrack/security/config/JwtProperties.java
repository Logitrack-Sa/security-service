package com.logitrack.security.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propiedades de configuración para la emisión y gestión del ciclo de vida de los JWT.
 *
 * <p>Define los parámetros criptográficos y de reclamos (claims) requeridos por el contrato
 * del Sprint 2 para la autenticación descentralizada entre microservicios:</p>
 * <ul>
 *   <li>{@code privateKeyLocation}: Ubicación de la clave privada RSA (formato PEM) montada desde secretos.</li>
 *   <li>{@code publicKeyLocation}: Ubicación opcional de la clave pública RSA (formato PEM).</li>
 *   <li>{@code keyId}: Identificador de clave (kid) incluido en la cabecera JOSE del token para posibilitar rotación.</li>
 *   <li>{@code issuer}: Identificador URI del emisor confiable (claim iss).</li>
 *   <li>{@code audiences}: Lista de audiencias permitidas y destinatarias del token (claim aud).</li>
 *   <li>{@code ttlSeconds}: Tiempo de vida en segundos antes de la expiración del token (claim exp).</li>
 *   <li>{@code expirationMs}: Tiempo de expiración opcional en milisegundos para compatibilidad con perfiles centralizados.</li>
 * </ul>
 *
 * @param privateKeyLocation ruta o URI al archivo PEM con la clave privada RSA.
 * @param publicKeyLocation ruta o URI opcional al archivo PEM con la clave pública RSA.
 * @param keyId identificador de clave presente en la cabecera {@code kid}.
 * @param issuer emisor esperado en el claim {@code iss}.
 * @param audiences lista de servicios destinatarios esperados en el claim {@code aud}.
 * @param ttlSeconds duración en segundos de validez de cada token emitido.
 * @param expirationMs expiración opcional en milisegundos proveniente de Config Server.
 */
@ConfigurationProperties("logitrack.security.jwt")
public record JwtProperties(
        String privateKeyLocation,
        String publicKeyLocation,
        String keyId,
        String issuer,
        List<String> audiences,
        long ttlSeconds,
        Long expirationMs
) {

    /**
     * Constructor canónico con normalización defensiva y soporte para milisegundos o segundos.
     *
     * @param privateKeyLocation ruta a la clave privada o nulo si se usa clave efímera.
     * @param publicKeyLocation ruta a la clave pública o nulo.
     * @param keyId identificador de clave {@code kid} (por defecto "logitrack-main").
     * @param issuer emisor del token (por defecto "https://security-service").
     * @param audiences audiencias permitidas (por defecto security-service, courier-service y shipment-service).
     * @param ttlSeconds duración del token en segundos (por defecto 3600).
     * @param expirationMs expiración opcional en milisegundos.
     */
    public JwtProperties {
        if (keyId == null || keyId.isBlank()) {
            keyId = "logitrack-main";
        }
        if (issuer == null || issuer.isBlank()) {
            issuer = "https://security-service";
        }
        if (audiences == null || audiences.isEmpty()) {
            audiences = List.of("security-service", "courier-service", "shipment-service");
        }
        if (expirationMs != null && expirationMs > 0) {
            ttlSeconds = expirationMs / 1000;
        } else if (ttlSeconds <= 0) {
            ttlSeconds = 3600L;
        }
    }
}
