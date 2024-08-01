package com.guettafa.JwtBackend.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String JWT_SECRET = "rS7Fq7C3e6B1H2kI9A0L1P2M3Q4R5S6T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q=";

    public String extractEmail(String jwt) {
        // The subject should be the email for the user
        return extractClaim(jwt, Claims::getSubject);
    }

    private Date extractExpiration(String jwt) {
        return extractClaim(jwt, Claims::getExpiration);
    }

    /**
     * Generic method that can be used to extract
     * any data from the payload
     */
    private <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver) {
        final Claims claims = extractClaims(jwt);
        return claimsResolver.apply(claims);
    }

    /**
     * To verify it authenticity
     * -
     * Generate a key used to sign the token using the Secret Key
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * extract payload from token and transform it to claims
     * @param jwt
     * @return payload informations in many claims
     */
    private Claims extractClaims(String jwt) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody(); // get payload
    }


    // To generate token only with user information
    public String generateJWT(UserDetails userDetails) {
        return generateJWT(new HashMap<>(), userDetails);
    }

    // To generate token with extra claims
    public String generateJWT(
            Map<String, Object> extraClaims,
            UserDetails userDetails)
    {
        return Jwts
                .builder()
                    .setClaims(extraClaims)
                    .setSubject(userDetails.getUsername())
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                    .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    private boolean isTokenExpired(String jwt) {
        return new Date(System.currentTimeMillis())
                .after(extractExpiration(jwt));
    }

    public boolean isTokenValid(String jwt, UserDetails userDetails) {
        final String email = extractEmail(jwt);
        return (email.equals(userDetails.getUsername())) && !isTokenExpired(jwt);
    }
}
