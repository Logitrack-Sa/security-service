package com.logitrack.security.service;

import com.logitrack.security.entity.VerificationToken;
import com.logitrack.security.exception.VerificationTokenException;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.repository.VerificationTokenRepository;
import java.util.Locale;
import java.util.UUID;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Confirmación y renovación atómicas, serializadas mediante bloqueo de la cuenta. */
@Service
public class EmailVerificationService {
    private final UserRepository users;
    private final VerificationTokenRepository tokens;
    private final EmailService email;

    public EmailVerificationService(UserRepository users, VerificationTokenRepository tokens, EmailService email) {
        this.users = users;
        this.tokens = tokens;
        this.email = email;
    }

    @Transactional
    @CacheEvict(value = "user_profiles", key = "'user::username::' + #result")
    public UUID verify(String value) {
        UUID userId = tokens.findUserIdByToken(value).orElseThrow(() -> new VerificationTokenException(false));
        // Siempre bloquear primero la cuenta, igual que en resend; consultar luego el estado actual del token.
        var user = users.findLockedById(userId).orElseThrow(() -> new VerificationTokenException(false));
        var token = tokens.findLockedByToken(value).orElseThrow(() -> new VerificationTokenException(false));
        if (token.isRevoked() || user.isEmailVerified()) {
            throw new VerificationTokenException(false);
        }
        if (token.isExpired()) {
            throw new VerificationTokenException(true);
        }
        token.setRevoked(true);
        user.setEnabled(true);
        user.setEmailVerified(true);
        tokens.findAllByUserAndRevokedFalse(user).forEach(t -> t.setRevoked(true));
        return userId;
    }

    @Transactional
    public void resend(String address) {
        var user = users.findLockedByEmail(address.strip().toLowerCase(Locale.ROOT)).orElse(null);
        // Respuesta uniforme para no revelar cuentas existentes o ya verificadas.
        if (user == null || user.isEmailVerified()) {
            return;
        }
        tokens.findAllByUserAndRevokedFalse(user).forEach(t -> t.setRevoked(true));
        var token = tokens.save(new VerificationToken(user, 24));
        String recipient = user.getEmail();
        String value = token.getToken();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                email.sendVerificationEmail(recipient, value);
            }
        });
    }
}
