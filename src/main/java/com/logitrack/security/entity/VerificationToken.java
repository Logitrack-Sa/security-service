package com.logitrack.security.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Entidad de persistencia para tokens de verificación de correo electrónico de un solo uso.
 *
 * <p>Genera un UUID v4 seguro con expiración a 24 horas y soporte para revocación inmediata.</p>
 */
@Entity
@Table(name = "verification_tokens", indexes = {
    @Index(name = "idx_verification_token_value", columnList = "token", unique = true)
})
@Getter
@Setter
@NoArgsConstructor
public class VerificationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 36)
    private String token; // UUID v4

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked;

    public VerificationToken(User user, long ttlHours) {
        this.token = UUID.randomUUID().toString();
        this.user = user;
        this.expiryDate = Instant.now().plus(ttlHours, ChronoUnit.HOURS);
        this.revoked = false;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }
}
