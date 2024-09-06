package com.nazim.authserver.repositories;

import com.nazim.authserver.entities.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PermissionRepository extends JpaRepository<Permission, Long> {
    List<Permission> findByMethodAndEndpoint(String method, String endpoint);
}

