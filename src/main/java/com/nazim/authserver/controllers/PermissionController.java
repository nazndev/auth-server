package com.nazim.authserver.controllers;

import com.nazim.authserver.entities.Permission;
import com.nazim.authserver.responses.ApiResponse;
import com.nazim.authserver.services.PermissionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth/permissions")
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionService permissionService;

    @PostMapping
    @PreAuthorize("hasPermission('/api/auth/permissions', 'POST')")
    public ResponseEntity<ApiResponse<Permission>> createPermission(@RequestBody Permission permission) {
        Permission createdPermission = permissionService.addPermission(permission);
        return ResponseEntity.ok(new ApiResponse<>("success", "Permission created successfully", createdPermission));
    }

    @GetMapping("/{permissionId}")
    public ResponseEntity<ApiResponse<Permission>> viewPermission(@PathVariable Long permissionId) {
        Permission permission = permissionService.getPermissionById(permissionId);
        return ResponseEntity.ok(new ApiResponse<>("success", "Permission retrieved successfully", permission));
    }

    @PutMapping("/{permissionId}")
    @PreAuthorize("hasPermission('/api/auth/permissions/**', 'PUT')")
    public ResponseEntity<ApiResponse<Permission>> updatePermission(@PathVariable Long permissionId, @RequestBody Permission permission) {
        Permission updatedPermission = permissionService.updatePermission(permissionId, permission);
        return ResponseEntity.ok(new ApiResponse<>("success", "Permission updated successfully", updatedPermission));
    }

    @DeleteMapping("/{permissionId}")
    @PreAuthorize("hasPermission('/api/auth/permissions/**', 'DELETE')")
    public ResponseEntity<ApiResponse<String>> deletePermission(@PathVariable Long permissionId) {
        permissionService.deletePermission(permissionId);
        return ResponseEntity.ok(new ApiResponse<>("success", "Permission deleted successfully", null));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<Permission>>> getAllPermissions() {
        List<Permission> permissions = permissionService.getAllPermissions();
        return ResponseEntity.ok(new ApiResponse<>("success", "Permissions retrieved successfully", permissions));
    }
}
