package com.nazim.authserver.security;

import com.nazim.authserver.services.PermissionEvaluatorService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Component
@RequiredArgsConstructor
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final PermissionEvaluatorService permissionEvaluatorService;

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || targetDomainObject == null || permission == null) {
            return false;
        }

        String endpoint = (String) targetDomainObject;
        String method = (String) permission;

        return permissionEvaluatorService.hasPermission(authentication, endpoint, method);
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        // Optionally implement this if needed for more complex permission checking
        return false;
    }
}
