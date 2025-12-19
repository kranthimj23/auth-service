package com.mobilebanking.auth.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserPrincipal {
    private UUID userId;
    private String username;
    private Set<String> roles;
}
