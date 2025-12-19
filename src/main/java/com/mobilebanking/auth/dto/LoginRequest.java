package com.mobilebanking.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Login request payload")
public class LoginRequest {

    @NotBlank(message = "Username or email is required")
    @Size(max = 100, message = "Username or email must not exceed 100 characters")
    @Schema(description = "Username or email address", example = "john.doe@example.com")
    private String usernameOrEmail;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    @Schema(description = "User password", example = "SecureP@ss123")
    private String password;

    @Schema(description = "Device identifier for token tracking", example = "device-uuid-123")
    private String deviceId;
}
