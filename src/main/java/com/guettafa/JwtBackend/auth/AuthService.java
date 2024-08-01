package com.guettafa.JwtBackend.auth;

import com.guettafa.JwtBackend.auth.dto.AuthResponse;
import com.guettafa.JwtBackend.auth.dto.LoginRequest;
import com.guettafa.JwtBackend.auth.dto.RegisterRequest;
import com.guettafa.JwtBackend.customer.Customer;
import com.guettafa.JwtBackend.customer.CustomerService;
import com.guettafa.JwtBackend.customer.enums.Role;
import com.guettafa.JwtBackend.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final CustomerService customerService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register(RegisterRequest request) {
        String jwt = jwtService.generateJWT(customerService.saveCustomer(Customer
                .builder()
                    .email(request.email())
                    .pwd(passwordEncoder.encode(request.password()))
                    .role(Role.USER)
                .build())
        );
        return AuthResponse.builder().token(jwt).build();
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );
        // If everything correct
        return AuthResponse
                .builder()
                    .token(jwtService.generateJWT(customerService.getByEmail(request.email())))
                .build();
    }
}
