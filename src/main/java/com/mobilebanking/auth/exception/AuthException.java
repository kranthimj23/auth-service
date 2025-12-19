package com.mobilebanking.auth.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class AuthException extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;

    public AuthException(String message, HttpStatus status, String errorCode) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
    }

    public static AuthException invalidCredentials() {
        return new AuthException("Invalid username/email or password", HttpStatus.UNAUTHORIZED, "AUTH_001");
    }

    public static AuthException accountLocked() {
        return new AuthException("Account is locked due to too many failed login attempts", HttpStatus.FORBIDDEN, "AUTH_002");
    }

    public static AuthException accountDisabled() {
        return new AuthException("Account is disabled", HttpStatus.FORBIDDEN, "AUTH_003");
    }

    public static AuthException invalidToken() {
        return new AuthException("Invalid or expired token", HttpStatus.UNAUTHORIZED, "AUTH_004");
    }

    public static AuthException tokenExpired() {
        return new AuthException("Token has expired", HttpStatus.UNAUTHORIZED, "AUTH_005");
    }

    public static AuthException refreshTokenRevoked() {
        return new AuthException("Refresh token has been revoked", HttpStatus.UNAUTHORIZED, "AUTH_006");
    }

    public static AuthException emailAlreadyExists() {
        return new AuthException("Email already registered", HttpStatus.CONFLICT, "AUTH_007");
    }

    public static AuthException usernameAlreadyExists() {
        return new AuthException("Username already taken", HttpStatus.CONFLICT, "AUTH_008");
    }

    public static AuthException passwordMismatch() {
        return new AuthException("Password and confirmation do not match", HttpStatus.BAD_REQUEST, "AUTH_009");
    }

    public static AuthException userNotFound() {
        return new AuthException("User not found", HttpStatus.NOT_FOUND, "AUTH_010");
    }

    public static AuthException oauthError(String message) {
        return new AuthException("OAuth error: " + message, HttpStatus.BAD_REQUEST, "AUTH_011");
    }
}
