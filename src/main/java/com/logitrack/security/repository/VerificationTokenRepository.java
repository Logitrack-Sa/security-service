package com.logitrack.security.repository;

import com.logitrack.security.entity.User;
import com.logitrack.security.entity.VerificationToken;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Repositorio Spring Data JPA para la persistencia y consulta de tokens de verificación.
 */
@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    @Query("select t.user.id from VerificationToken t where t.token = :token")
    Optional<UUID> findUserIdByToken(@Param("token") String token);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<VerificationToken> findLockedByToken(String token);

    Optional<VerificationToken> findByToken(String token);

    Optional<VerificationToken> findByTokenAndRevokedFalse(String token);

    List<VerificationToken> findAllByUser(User user);

    List<VerificationToken> findAllByUserAndRevokedFalse(User user);

    void deleteByUser(User user);
}
