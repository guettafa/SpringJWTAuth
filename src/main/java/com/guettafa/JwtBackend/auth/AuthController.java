package com.guettafa.JwtBackend.auth;

import com.guettafa.JwtBackend.auth.dto.AuthResponse;
import com.guettafa.JwtBackend.auth.dto.LoginRequest;
import com.guettafa.JwtBackend.auth.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @RequestBody RegisterRequest request)
    {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> register(
            @RequestBody LoginRequest request)
    {
        return ResponseEntity.ok(authService.login(request));
    }


}
