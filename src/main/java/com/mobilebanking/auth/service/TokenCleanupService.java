package com.mobilebanking.auth.service;

import com.mobilebanking.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Scheduled(cron = "0 0 */6 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Starting cleanup of expired and revoked refresh tokens");
        int deletedCount = refreshTokenRepository.deleteExpiredAndRevokedTokens(LocalDateTime.now());
        log.info("Cleaned up {} expired/revoked refresh tokens", deletedCount);
    }
}
