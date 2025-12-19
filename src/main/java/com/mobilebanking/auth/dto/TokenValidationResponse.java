package com.mobilebanking.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Token validation response")
public class TokenValidationResponse {

    @Schema(description = "Whether the token is valid", example = "true")
    private boolean valid;

    @Schema(description = "User ID if token is valid", example = "550e8400-e29b-41d4-a716-446655440000")
    private UUID userId;

    @Schema(description = "Username if token is valid", example = "john_doe")
    private String username;

    @Schema(description = "User roles if token is valid", example = "[\"ROLE_USER\"]")
    private Set<String> roles;

    @Schema(description = "Error message if token is invalid", example = "Token has expired")
    private String errorMessage;
}
