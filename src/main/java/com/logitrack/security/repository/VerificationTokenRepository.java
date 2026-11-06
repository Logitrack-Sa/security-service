package com.logitrack.security.repository;

import com.logitrack.security.entity.User;
import com.logitrack.security.entity.VerificationToken;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repositorio Spring Data JPA para la persistencia y consulta de tokens de verificación.
 */
@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    Optional<VerificationToken> findByToken(String token);

    Optional<VerificationToken> findByTokenAndRevokedFalse(String token);

    List<VerificationToken> findAllByUser(User user);

    List<VerificationToken> findAllByUserAndRevokedFalse(User user);

    void deleteByUser(User user);
}
