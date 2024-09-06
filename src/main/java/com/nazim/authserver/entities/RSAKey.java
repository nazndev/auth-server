package com.nazim.authserver.entities;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "rsa_keys")
@Data
public class RSAKey extends BaseEntity {

    @Lob
    private String privateKey;

    @Lob
    private String publicKey;

    private boolean active;

    @Column(name = "key_id", unique = true)
    private String keyId;

}
