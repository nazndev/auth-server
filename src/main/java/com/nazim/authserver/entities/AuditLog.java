package com.nazim.authserver.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_log")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String entityName;
    private Long entityId;
    private String action;  // CREATE, UPDATE, DELETE, etc.
    private String performedBy;  // User who performed the action
    private LocalDateTime performedAt = LocalDateTime.now();  // Timestamp
    private String changes;  // JSON representation of entity changes

    public AuditLog(String entityName, Long entityId, String action, String performedBy, String changes) {
        this.entityName = entityName;
        this.entityId = entityId;
        this.action = action;
        this.performedBy = performedBy;
        this.changes = changes;
    }
}
