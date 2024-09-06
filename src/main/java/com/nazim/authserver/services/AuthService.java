package com.nazim.authserver.services;

import com.nazim.authserver.entities.User;
import com.nazim.authserver.repositories.UserRepository;
import com.nazim.authserver.utils.JwtSigningKeyResolver;
import com.nazim.authserver.utils.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final JwtSigningKeyResolver jwtSigningKeyResolver;

    // Login method with grantType support
    public String login(String username, String password, String grantType) {
        if ("password".equals(grantType)) {
            // Password grant type logic
            return authenticateWithPassword(username, password);
        } else if ("refresh_token".equals(grantType)) {
            // Refresh token logic could go here, or you could handle it elsewhere
            throw new IllegalArgumentException("Refresh token grant type must use the refresh token endpoint");
        } else {
            throw new IllegalArgumentException("Unsupported grant type: " + grantType);
        }
    }

    // Authenticate with password grant type
    private String authenticateWithPassword(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (passwordEncoder.matches(password, user.getPassword())) {
            return jwtTokenUtil.generateAccessToken(user);  // Generate JWT
        } else {
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    // Change password method
    public void changePassword(String username, String oldPassword, String newPassword, String confirmPassword) {
        if (!newPassword.equals(confirmPassword)) {
            throw new IllegalArgumentException("New password and confirmation password do not match");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new BadCredentialsException("Old password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    // Refresh token method
    public String refreshToken(String token) {
        if (jwtTokenUtil.validateToken(token, jwtSigningKeyResolver)) {  // Pass the signing key resolver
            if (!jwtTokenUtil.isTokenExpired(token, jwtSigningKeyResolver)) {  // Pass the signing key resolver
                User user = jwtTokenUtil.getUserFromToken(token, jwtSigningKeyResolver);  // Pass the signing key resolver
                return jwtTokenUtil.generateRefreshToken(user);  // Generate new token
            } else {
                throw new RuntimeException("Token has expired");
            }
        } else {
            throw new RuntimeException("Invalid token");
        }
    }

    // Standalone token validation method
    public boolean validateToken(String token) {
        return jwtTokenUtil.validateToken(token, jwtSigningKeyResolver);  // Pass the signing key resolver
    }
}
