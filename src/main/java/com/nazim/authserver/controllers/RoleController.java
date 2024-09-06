package com.nazim.authserver.controllers;

import com.nazim.authserver.entities.Role;
import com.nazim.authserver.responses.ApiResponse;
import com.nazim.authserver.services.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    // Create a new role
    @PostMapping
    @PreAuthorize("hasPermission('/api/auth/roles', 'POST')")
    public ResponseEntity<ApiResponse<Role>> createRole(@RequestParam String roleName) {
        Role createdRole = roleService.addRole(roleName);
        return ResponseEntity.ok(new ApiResponse<>("success", "Role created successfully", createdRole));
    }

    // View a specific role by ID
    @GetMapping("/{roleId}")
    public ResponseEntity<ApiResponse<Role>> viewRole(@PathVariable Long roleId) {
        Role role = roleService.getRoleById(roleId);
        return ResponseEntity.ok(new ApiResponse<>("success", "Role retrieved successfully", role));
    }

    // Update a specific role by ID
    @PutMapping("/{roleId}")
    @PreAuthorize("hasPermission('/api/auth/roles/**', 'PUT')")
    public ResponseEntity<ApiResponse<Role>> updateRole(@PathVariable Long roleId, @RequestParam String roleName) {
        Role updatedRole = roleService.updateRole(roleId, roleName);
        return ResponseEntity.ok(new ApiResponse<>("success", "Role updated successfully", updatedRole));
    }

    // Delete a specific role by ID
    @DeleteMapping("/{roleId}")
    @PreAuthorize("hasPermission('/api/auth/roles/**', 'DELETE')")
    public ResponseEntity<ApiResponse<String>> deleteRole(@PathVariable Long roleId) {
        roleService.deleteRole(roleId);
        return ResponseEntity.ok(new ApiResponse<>("success", "Role deleted successfully", null));
    }
}
