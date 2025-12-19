package com.mobilebanking.auth.repository;

import com.mobilebanking.auth.entity.UserAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserAuthRepository extends JpaRepository<UserAuth, UUID> {

    Optional<UserAuth> findByEmail(String email);

    Optional<UserAuth> findByUsername(String username);

    @Query("SELECT u FROM UserAuth u WHERE u.email = :identifier OR u.username = :identifier")
    Optional<UserAuth> findByEmailOrUsername(@Param("identifier") String identifier);

    boolean existsByEmail(String email);

    boolean existsByUsername(String username);

    @Modifying
    @Query("UPDATE UserAuth u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.id = :userId")
    void incrementFailedAttempts(@Param("userId") UUID userId);

    @Modifying
    @Query("UPDATE UserAuth u SET u.failedLoginAttempts = 0 WHERE u.id = :userId")
    void resetFailedAttempts(@Param("userId") UUID userId);

    @Modifying
    @Query("UPDATE UserAuth u SET u.lastLoginAt = :loginTime, u.lastLoginIp = :ip WHERE u.id = :userId")
    void updateLastLogin(@Param("userId") UUID userId, @Param("loginTime") LocalDateTime loginTime, @Param("ip") String ip);

    @Modifying
    @Query("UPDATE UserAuth u SET u.accountNonLocked = false, u.lockedUntil = :lockedUntil WHERE u.id = :userId")
    void lockAccount(@Param("userId") UUID userId, @Param("lockedUntil") LocalDateTime lockedUntil);

    @Modifying
    @Query("UPDATE UserAuth u SET u.accountNonLocked = true, u.lockedUntil = null, u.failedLoginAttempts = 0 WHERE u.id = :userId")
    void unlockAccount(@Param("userId") UUID userId);
}
