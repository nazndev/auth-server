package com.nazim.authserver.services;

import com.nazim.authserver.entities.Permission;
import com.nazim.authserver.entities.Role;
import com.nazim.authserver.entities.User;
import com.nazim.authserver.repositories.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class PermissionEvaluatorService {

    private static final Logger logger = LoggerFactory.getLogger(PermissionEvaluatorService.class);

    private final PermissionRepository permissionRepository;

    /**
     * Checks if a user has permission to access a specific endpoint with a given method.
     *
     * @param authentication the current authentication object
     * @param endpoint       the API endpoint being accessed
     * @param method         the HTTP method (GET, POST, etc.) used in the request
     * @return true if the user has permission, false otherwise
     */
    public boolean hasPermission(Authentication authentication, String endpoint, String method) {
        User user = (User) authentication.getPrincipal();
        if (user == null) {
            logger.error("User principal is null. Authentication might not be valid.");
            throw new UsernameNotFoundException("User not authenticated or found.");
        }

        Set<Role> roles = user.getRoles();
        if (roles.isEmpty()) {
            logger.warn("User {} does not have any roles assigned.", user.getUsername());
            return false;
        }

        Set<Permission> permissions = new HashSet<>();
        roles.forEach(role -> permissions.addAll(role.getPermissions()));

        AntPathMatcher pathMatcher = new AntPathMatcher();
        for (Permission permission : permissions) {
            if (permission.getMethod().equalsIgnoreCase(method) &&
                    pathMatcher.match(permission.getEndpoint(), endpoint)) {
                logger.debug("Permission granted for user {} to access endpoint {} with method {}",
                        user.getUsername(), endpoint, method);
                return true;
            }
        }

        logger.warn("Permission denied for user {} to access endpoint {} with method {}",
                user.getUsername(), endpoint, method);
        return false;
    }
}
