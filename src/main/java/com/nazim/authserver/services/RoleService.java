package com.nazim.authserver.services;

import com.nazim.authserver.entities.Role;
import com.nazim.authserver.repositories.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class RoleService {

    private final RoleRepository roleRepository;

    // Add a new role
    public Role addRole(String roleName) {
        Role role = new Role();
        role.setName(roleName);
        return roleRepository.save(role);
    }

    // Find role by name
    public Role findByName(String roleName) {
        return roleRepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found"));
    }

    // Find role by ID
    public Role getRoleById(Long roleId) {
        return roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found"));
    }

    // Update role name
    public Role updateRole(Long roleId, String newRoleName) {
        Role role = getRoleById(roleId);
        role.setName(newRoleName);
        return roleRepository.save(role);
    }

    // Delete role by ID
    public void deleteRole(Long roleId) {
        Role role = getRoleById(roleId);
        roleRepository.delete(role);
    }
}
