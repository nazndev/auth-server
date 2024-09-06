package com.nazim.authserver.services;

import com.nazim.authserver.entities.Permission;
import com.nazim.authserver.repositories.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class PermissionService {

    private final PermissionRepository permissionRepository;

    // Method to add permission
    public Permission addPermission(Permission permission) {
        return permissionRepository.save(permission);
    }

    // Method to fetch all permissions
    public List<Permission> getAllPermissions() {
        return permissionRepository.findAll();
    }

    // Method to fetch permission by ID
    public Permission getPermissionById(Long id) {
        return permissionRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Permission not found"));
    }

    // Method to update permission
    public Permission updatePermission(Long id, Permission newPermissionData) {
        Permission existingPermission = getPermissionById(id);
        existingPermission.setName(newPermissionData.getName());
        existingPermission.setMethod(newPermissionData.getMethod());
        existingPermission.setEndpoint(newPermissionData.getEndpoint());
        existingPermission.setMicroservice(newPermissionData.getMicroservice());
        return permissionRepository.save(existingPermission);
    }

    // Method to delete permission
    public void deletePermission(Long id) {
        Permission permission = getPermissionById(id);
        permissionRepository.delete(permission);
    }
}
