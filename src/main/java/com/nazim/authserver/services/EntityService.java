package com.nazim.authserver.services;

import com.nazim.authserver.audit.AuditListener;
import com.nazim.authserver.entities.BaseEntity;
import com.nazim.authserver.repositories.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class EntityService {

    private final AuditLogRepository auditLogRepository;
    private final AuditListener auditListener;

    public BaseEntity readEntity(BaseEntity entity) {
        // Manually log the read/view operation
        auditListener.logChange(entity, "READ");
        return entity;
    }
}
