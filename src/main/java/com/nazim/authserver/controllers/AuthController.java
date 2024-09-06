package com.nazim.authserver.controllers;

import com.nazim.authserver.payloads.ChangePasswordRequest;
import com.nazim.authserver.payloads.LoginRequest;
import com.nazim.authserver.payloads.TokenRefreshRequest;
import com.nazim.authserver.responses.ApiResponse;
import com.nazim.authserver.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // Login API (supports only password grant type)
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<String>> login(@RequestBody LoginRequest loginRequest) {
        if (!"password".equals(loginRequest.getGrantType())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("failure", "Unsupported grant type", null));
        }
        try {
            String token = authService.login(loginRequest.getUsername(), loginRequest.getPassword(), loginRequest.getGrantType());
            return ResponseEntity.ok(new ApiResponse<>("success", "Login successful", token));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ApiResponse<>("failure", "Login failed: " + ex.getMessage(), null));
        }
    }

    // Change Password API
    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @AuthenticationPrincipal Authentication authentication,
            @RequestBody ChangePasswordRequest request) {
        try {
            authService.changePassword(authentication.getName(), request.getOldPassword(), request.getNewPassword(), request.getConfirmPassword());
            return ResponseEntity.ok(new ApiResponse<>("success", "Password changed successfully", null));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>("failure", "Failed to change password: " + ex.getMessage(), null));
        }
    }

    // Token validation API
    @GetMapping("/validate-token")
    public ResponseEntity<ApiResponse<Boolean>> validateToken(@RequestHeader("Authorization") String token) {
        boolean isValid = authService.validateToken(token.replace("Bearer ", ""));
        if (isValid) {
            return ResponseEntity.ok(new ApiResponse<>("success", "Token is valid", true));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ApiResponse<>("failure", "Invalid or expired token", false));
        }
    }

    // Refresh Token API (for the refresh_token grant type)
    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<String>> refreshToken(
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody TokenRefreshRequest tokenRequest) {
        try {
            // Extract the refresh token from the Authorization header
            String refreshToken = authorizationHeader.replace("Bearer ", "");

            // Ensure grant_type is "refresh_token"
            if (!"refresh_token".equals(tokenRequest.getGrantType())) {
                throw new IllegalArgumentException("Invalid grant_type");
            }

            String newToken = authService.refreshToken(refreshToken);
            return ResponseEntity.ok(new ApiResponse<>("success", "Token refreshed", newToken));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("failure", "Token refresh failed: " + ex.getMessage(), null));
        }
    }
}
