package com.nazim.authserver.entities;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "microservices")
@Data
public class Microservice extends BaseEntity {

    @Column(unique = true, nullable = false)
    private String name;  // Name of the microservice

    private String description;  // Description of the microservice

    private String baseUrl;  // Base URL for the microservice

    @Lob
    private String publicKey;  // Public key for JWT verification for the microservice
}
