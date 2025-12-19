package com.mobilebanking.auth.service;

import com.mobilebanking.auth.dto.*;
import com.mobilebanking.auth.entity.RefreshToken;
import com.mobilebanking.auth.entity.UserAuth;
import com.mobilebanking.auth.exception.AuthException;
import com.mobilebanking.auth.repository.RefreshTokenRepository;
import com.mobilebanking.auth.repository.UserAuthRepository;
import com.mobilebanking.auth.security.JwtTokenProvider;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

@Service
@Slf4j
public class AuthService {

    private final UserAuthRepository userAuthRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final Counter loginSuccessCounter;
    private final Counter loginFailureCounter;
    private final Counter registrationCounter;

    @Value("${auth.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${auth.lock-duration-minutes:30}")
    private int lockDurationMinutes;

    public AuthService(
            UserAuthRepository userAuthRepository,
            RefreshTokenRepository refreshTokenRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenProvider jwtTokenProvider,
            MeterRegistry meterRegistry) {
        this.userAuthRepository = userAuthRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        
        this.loginSuccessCounter = Counter.builder("auth.login.success")
                .description("Number of successful logins")
                .register(meterRegistry);
        this.loginFailureCounter = Counter.builder("auth.login.failure")
                .description("Number of failed logins")
                .register(meterRegistry);
        this.registrationCounter = Counter.builder("auth.registration")
                .description("Number of user registrations")
                .register(meterRegistry);
    }

    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent) {
        log.info("Login attempt for user: {}", request.getUsernameOrEmail());

        UserAuth user = userAuthRepository.findByEmailOrUsername(request.getUsernameOrEmail())
                .orElseThrow(() -> {
                    loginFailureCounter.increment();
                    return AuthException.invalidCredentials();
                });

        if (user.isLocked()) {
            loginFailureCounter.increment();
            throw AuthException.accountLocked();
        }

        if (!user.getEnabled()) {
            loginFailureCounter.increment();
            throw AuthException.accountDisabled();
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            handleFailedLogin(user);
            loginFailureCounter.increment();
            throw AuthException.invalidCredentials();
        }

        user.resetFailedAttempts();
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(ipAddress);
        userAuthRepository.save(user);

        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getUsername(), user.getRoles());
        String refreshToken = createRefreshToken(user.getId(), ipAddress, userAgent, request.getDeviceId());

        loginSuccessCounter.increment();
        log.info("Successful login for user: {}", user.getUsername());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getAccessTokenExpiration() / 1000)
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles())
                .build();
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Registration attempt for email: {}", request.getEmail());

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw AuthException.passwordMismatch();
        }

        if (userAuthRepository.existsByEmail(request.getEmail())) {
            throw AuthException.emailAlreadyExists();
        }

        if (userAuthRepository.existsByUsername(request.getUsername())) {
            throw AuthException.usernameAlreadyExists();
        }

        UserAuth user = UserAuth.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        user = userAuthRepository.save(user);

        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getUsername(), user.getRoles());
        String refreshToken = createRefreshToken(user.getId(), null, null, null);

        registrationCounter.increment();
        log.info("Successful registration for user: {}", user.getUsername());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getAccessTokenExpiration() / 1000)
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles())
                .build();
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request, String ipAddress, String userAgent) {
        log.debug("Refresh token request");

        RefreshToken storedToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(AuthException::invalidToken);

        if (!storedToken.isValid()) {
            if (storedToken.getRevoked()) {
                refreshTokenRepository.revokeAllUserTokens(storedToken.getUserId());
                log.warn("Reuse of revoked refresh token detected for user: {}", storedToken.getUserId());
            }
            throw AuthException.refreshTokenRevoked();
        }

        UserAuth user = userAuthRepository.findById(storedToken.getUserId())
                .orElseThrow(AuthException::userNotFound);

        if (!user.getEnabled() || user.isLocked()) {
            throw AuthException.accountDisabled();
        }

        String newRefreshToken = jwtTokenProvider.generateRefreshToken();
        refreshTokenRepository.rotateToken(request.getRefreshToken(), newRefreshToken);

        RefreshToken newToken = RefreshToken.builder()
                .token(newRefreshToken)
                .userId(user.getId())
                .expiresAt(LocalDateTime.now().plusSeconds(jwtTokenProvider.getRefreshTokenExpiration() / 1000))
                .issuedFromIp(ipAddress)
                .userAgent(userAgent)
                .deviceId(storedToken.getDeviceId())
                .build();
        refreshTokenRepository.save(newToken);

        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getUsername(), user.getRoles());

        log.debug("Token refreshed for user: {}", user.getUsername());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getAccessTokenExpiration() / 1000)
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles())
                .build();
    }

    @Transactional
    public void logout(String refreshToken) {
        refreshTokenRepository.revokeToken(refreshToken);
        log.debug("User logged out, refresh token revoked");
    }

    @Transactional
    public void logoutAll(UUID userId) {
        refreshTokenRepository.revokeAllUserTokens(userId);
        log.info("All sessions revoked for user: {}", userId);
    }

    public TokenValidationResponse validateToken(String token) {
        try {
            if (jwtTokenProvider.validateToken(token)) {
                UUID userId = jwtTokenProvider.getUserIdFromToken(token);
                String username = jwtTokenProvider.getUsernameFromToken(token);
                Set<String> roles = jwtTokenProvider.getRolesFromToken(token);

                return TokenValidationResponse.builder()
                        .valid(true)
                        .userId(userId)
                        .username(username)
                        .roles(roles)
                        .build();
            }
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
        }

        return TokenValidationResponse.builder()
                .valid(false)
                .errorMessage("Invalid or expired token")
                .build();
    }

    private void handleFailedLogin(UserAuth user) {
        user.incrementFailedAttempts();
        
        if (user.getFailedLoginAttempts() >= maxFailedAttempts) {
            user.setAccountNonLocked(false);
            user.setLockedUntil(LocalDateTime.now().plusMinutes(lockDurationMinutes));
            log.warn("Account locked for user: {} due to {} failed attempts", user.getUsername(), maxFailedAttempts);
        }
        
        userAuthRepository.save(user);
    }

    private String createRefreshToken(UUID userId, String ipAddress, String userAgent, String deviceId) {
        String token = jwtTokenProvider.generateRefreshToken();
        
        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .userId(userId)
                .expiresAt(LocalDateTime.now().plusSeconds(jwtTokenProvider.getRefreshTokenExpiration() / 1000))
                .issuedFromIp(ipAddress)
                .userAgent(userAgent)
                .deviceId(deviceId)
                .build();
        
        refreshTokenRepository.save(refreshToken);
        return token;
    }
}
