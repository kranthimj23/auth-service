package com.mobilebanking.auth.repository;

import com.mobilebanking.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUserIdAndRevokedFalse(UUID userId);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND rt.deviceId = :deviceId AND rt.revoked = false")
    Optional<RefreshToken> findActiveTokenByUserAndDevice(@Param("userId") UUID userId, @Param("deviceId") String deviceId);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.userId = :userId")
    void revokeAllUserTokens(@Param("userId") UUID userId);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.token = :token")
    void revokeToken(@Param("token") String token);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true, rt.replacedByToken = :newToken WHERE rt.token = :oldToken")
    void rotateToken(@Param("oldToken") String oldToken, @Param("newToken") String newToken);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now OR rt.revoked = true")
    int deleteExpiredAndRevokedTokens(@Param("now") LocalDateTime now);

    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.userId = :userId AND rt.revoked = false AND rt.expiresAt > :now")
    long countActiveTokensByUser(@Param("userId") UUID userId, @Param("now") LocalDateTime now);
}
