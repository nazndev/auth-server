package com.nazim.authserver.controllers;

import com.nazim.authserver.entities.Role;
import com.nazim.authserver.entities.User;
import com.nazim.authserver.responses.ApiResponse;
import com.nazim.authserver.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/auth/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    // Create a new user
    @PostMapping
    @PreAuthorize("hasPermission('/api/auth/users', 'POST')")
    public ResponseEntity<ApiResponse<User>> createUser(@RequestParam String username,
                                                        @RequestParam String password,
                                                        @RequestBody Set<Role> roles) {
        User createdUser = userService.addUser(username, password, roles);
        return ResponseEntity.ok(new ApiResponse<>("success", "User created successfully", createdUser));
    }

    // View a specific user by ID
    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponse<User>> viewUser(@PathVariable Long userId) {
        User user = userService.getUserById(userId);
        return ResponseEntity.ok(new ApiResponse<>("success", "User retrieved successfully", user));
    }

    // Update a specific user by ID
    @PutMapping("/{userId}")
    @PreAuthorize("hasPermission('/api/auth/users/**', 'PUT')")
    public ResponseEntity<ApiResponse<User>> updateUser(@PathVariable Long userId, @RequestBody User user) {
        User updatedUser = userService.updateUser(userId, user);
        return ResponseEntity.ok(new ApiResponse<>("success", "User updated successfully", updatedUser));
    }

    // Delete a specific user by ID
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasPermission('/api/auth/users/**', 'DELETE')")
    public ResponseEntity<ApiResponse<String>> deleteUser(@PathVariable Long userId) {
        userService.deleteUser(userId);
        return ResponseEntity.ok(new ApiResponse<>("success", "User deleted successfully", null));
    }
}
