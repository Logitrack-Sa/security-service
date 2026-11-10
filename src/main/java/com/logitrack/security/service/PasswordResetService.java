package com.logitrack.security.service;

import com.logitrack.security.entity.PasswordResetToken;
import com.logitrack.security.repository.PasswordResetTokenRepository;
import com.logitrack.security.repository.UserRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;

@Service
public class PasswordResetService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final UserRepository users;
    private final PasswordResetTokenRepository tokens;
    private final PasswordEncoder encoder;
    private final EmailService email;

    public PasswordResetService(UserRepository users, PasswordResetTokenRepository tokens,
                                PasswordEncoder encoder, EmailService email) {
        this.users = users;
        this.tokens = tokens;
        this.encoder = encoder;
        this.email = email;
    }

    @Transactional
    public void request(String address) {
        var user = users.findLockedByEmail(address.strip().toLowerCase(Locale.ROOT)).orElse(null);
        if (user == null || !user.isEnabled() || !user.isEmailVerified()) return;
        Instant now = Instant.now();
        var previous = tokens.findById(user.getId()).orElse(null);
        // No revocar el enlace vigente ni enviar más correos durante el período de espera.
        if (previous != null && previous.getCreatedAt().plusSeconds(60).isAfter(now)) return;
        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        tokens.save(new PasswordResetToken(user.getId(), hash(value), now));
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() {
                email.sendPasswordResetEmail(user.getEmail(), value);
            }
        });
    }

    @Transactional
    public void reset(String value, String password) {
        if (password.getBytes(StandardCharsets.UTF_8).length > 72)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La contraseña no debe superar 72 bytes.");
        String digest = hash(value);
        var userId = tokens.findUserIdByTokenHash(digest).orElseThrow(PasswordResetService::invalidLink);
        // El mismo orden de bloqueo serializa solicitudes, reenvíos y consumos concurrentes.
        var user = users.findLockedById(userId).orElseThrow(PasswordResetService::invalidLink);
        var current = tokens.findLockedByUserId(user.getId()).orElseThrow(PasswordResetService::invalidLink);
        if (!current.getTokenHash().equals(digest) || !current.getExpiresAt().isAfter(Instant.now())
                || !user.isEnabled() || !user.isEmailVerified()) throw invalidLink();
        user.updatePasswordHash(encoder.encode(password));
        tokens.delete(current);
    }

    private static ResponseStatusException invalidLink() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "El enlace no es válido, venció o ya fue utilizado. Solicitá uno nuevo.");
    }

    private static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 no disponible", impossible);
        }
    }
}
