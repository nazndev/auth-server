package com.nazim.authserver.entities;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "permissions")
@Data
public class Permission extends BaseEntity {

    private String name;  // Permission name like 'MANAGE_USERS'

    private String method;  // HTTP method like 'GET', 'POST', etc.

    private String endpoint;  // API endpoint like '/api/users/**'

    private String microservice;  // Microservice identifier like 'auth-server', 'user-service'
}
