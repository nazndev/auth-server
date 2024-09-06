package com.nazim.authserver.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nazim.authserver.entities.AuditLog;
import com.nazim.authserver.entities.BaseEntity;
import com.nazim.authserver.repositories.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import jakarta.persistence.*;

@Component
public class AuditListener {

    @Autowired
    private AuditLogRepository auditLogRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();  // Jackson ObjectMapper for JSON serialization

    @PrePersist
    public void prePersist(BaseEntity entity) {
        logChange(entity, "CREATE");
    }

    @PreUpdate
    public void preUpdate(BaseEntity entity) {
        logChange(entity, "UPDATE");
    }

    @PreRemove
    public void preRemove(BaseEntity entity) {
        logChange(entity, "DELETE");
    }

    public void logChange(BaseEntity entity, String action) {
        String entityName = entity.getClass().getSimpleName();
        Long entityId = entity.getId();
        String username = getCurrentUsername();
        String changes = getChanges(entity);  // Serialize the entity to JSON format for more detailed logs

        // Save the audit log to the database
        AuditLog auditLog = new AuditLog(entityName, entityId, action, username, changes);
        auditLogRepository.save(auditLog);
    }

    private String getCurrentUsername() {
        // Get the current user's username from the Spring Security context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return authentication.getName();
        }
        return "SYSTEM";  // Return 'SYSTEM' for non-authenticated or system actions
    }

    private String getChanges(BaseEntity entity) {
        try {
            // Serialize the entity to JSON format for tracking all changes
            return objectMapper.writeValueAsString(entity);
        } catch (Exception e) {
            // Fallback to string representation if serialization fails
            return entity.toString();
        }
    }
}
