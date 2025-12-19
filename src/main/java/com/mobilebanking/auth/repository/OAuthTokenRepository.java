package com.mobilebanking.auth.repository;

import com.mobilebanking.auth.entity.OAuthToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OAuthTokenRepository extends JpaRepository<OAuthToken, UUID> {

    Optional<OAuthToken> findByUserIdAndProvider(UUID userId, String provider);

    Optional<OAuthToken> findByProviderAndProviderId(String provider, String providerId);

    List<OAuthToken> findByUserId(UUID userId);

    boolean existsByUserIdAndProvider(UUID userId, String provider);

    @Modifying
    @Query("DELETE FROM OAuthToken ot WHERE ot.userId = :userId AND ot.provider = :provider")
    void deleteByUserIdAndProvider(@Param("userId") UUID userId, @Param("provider") String provider);

    @Modifying
    @Query("DELETE FROM OAuthToken ot WHERE ot.userId = :userId")
    void deleteAllByUserId(@Param("userId") UUID userId);
}
