package com.guettafa.JwtBackend.security.jwt.filter;

import com.guettafa.JwtBackend.security.jwt.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(

            // Received Request
            @NonNull HttpServletRequest request,
            // To extract data from the request and create a response
            @NonNull HttpServletResponse response,
            // Execute the next filter in the chain
            @NonNull FilterChain filterChain

    ) throws ServletException, IOException
    {
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request,response);
            return;
        }

        /**
         * For the request "Authorization" header on the response
         * so it will be stored as cookie in the frontend
         */
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // Check if the authHeader is valid quit if not
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // JWT start at 7 index so ill store it in a var 4 next steps
        jwt = authHeader.substring(7);

        // Extract the email from the JWT payload
        userEmail = jwtService.extractEmail(jwt);

        // If User is not authenticated
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // New instance of UserDetails based on found user email from JWT payload
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Check if the user email is the same as the token email
            if (jwtService.isTokenValid(jwt,userDetails)) {

                // Create an instance that "Made the user officially approved"
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Set the user as Authenticated
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        // Pass to the next filter to be executed
        filterChain.doFilter(request,response);
    }
}
