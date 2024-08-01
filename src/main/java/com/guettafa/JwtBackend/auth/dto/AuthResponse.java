package com.guettafa.JwtBackend.auth.dto;

import lombok.Builder;

@Builder
public record AuthResponse(
        String token
) { }
