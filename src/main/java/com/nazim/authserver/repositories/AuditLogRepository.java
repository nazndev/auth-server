package com.nazim.authserver.repositories;

import com.nazim.authserver.entities.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    // This interface will handle CRUD operations for the AuditLog entity
}
