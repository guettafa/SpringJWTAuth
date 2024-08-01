package com.guettafa.JwtBackend.auth.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
public record RegisterRequest(
        String email,
        String password
) { }
