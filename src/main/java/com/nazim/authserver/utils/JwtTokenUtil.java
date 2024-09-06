package com.nazim.authserver.utils;

import com.nazim.authserver.entities.RSAKey;
import com.nazim.authserver.entities.Role;
import com.nazim.authserver.entities.User;
import com.nazim.authserver.services.KeyRotationService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class JwtTokenUtil {

    private final KeyRotationService keyRotationService;

    @Value("${jwt.access-token-validity}")
    private long accessTokenValidity; // For Access Token (in minutes)

    @Value("${jwt.refresh-token-validity}")
    private long refreshTokenValidity; // For Refresh Token (in minutes)

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.audience}")
    private String audience;

    // Generate JWT Token with keyId included in the header for access or refresh token
    public String generateAccessToken(User user) {
        return generateToken(user, accessTokenValidity);
    }

    public String generateRefreshToken(User user) {
        return generateToken(user, refreshTokenValidity);
    }

    private String generateToken(User user, long expirationMinutes) {
        RSAKey activeKey = keyRotationService.getOrGenerateActiveKey();
        PrivateKey privateKey = getPrivateKey(activeKey.getPrivateKey());

        Instant now = Instant.now();

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "RS256")
                .setHeaderParam("kid", activeKey.getKeyId())  // Include key ID in the header
                .setSubject(user.getUsername())
                .setIssuer(issuer)
                .setAudience(audience)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(expirationMinutes * 60)))  // Use minutes to calculate expiration
                .claim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    // Validate JWT token using the provided signing key resolver
    public boolean validateToken(String token, SigningKeyResolver signingKeyResolver) {
        try {
            Jwts.parserBuilder()
                    .setSigningKeyResolver(signingKeyResolver)  // Use the custom key resolver
                    .build()
                    .parseClaimsJws(token);  // Validate the token
            return true;
        } catch (JwtException ex) {
            // Log error for better debugging
            System.out.println("JWT Validation failed: " + ex.getMessage());
            return false;
        }
    }

    // Extract user details from JWT token
    public User getUserFromToken(String token, SigningKeyResolver signingKeyResolver) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKeyResolver(signingKeyResolver)  // Use the signing key resolver
                .build()
                .parseClaimsJws(token)
                .getBody();

        String username = claims.getSubject();
        List<String> roles = claims.get("roles", List.class);

        User user = new User();
        user.setUsername(username);
        Set<Role> roleSet = roles.stream().map(roleName -> {
            Role role = new Role();
            role.setName(roleName);
            return role;
        }).collect(Collectors.toSet());

        user.setRoles(roleSet);

        return user;
    }

    // Get Private Key from base64 encoded string
    private PrivateKey getPrivateKey(String key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate private key", e);
        }
    }

    // Get Public Key from base64 encoded string
    public PublicKey getPublicKey(String key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate public key", e);
        }
    }

    // Check if the token has expired
    public boolean isTokenExpired(String token, SigningKeyResolver signingKeyResolver) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKeyResolver(signingKeyResolver)  // Use the provided SigningKeyResolver
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.getExpiration().before(new Date());  // Check expiration date
        } catch (JwtException e) {
            // If there was an issue parsing the token, treat it as expired or invalid
            return true;
        }
    }
}
