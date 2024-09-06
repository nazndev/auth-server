package com.nazim.authserver.repositories;

import com.nazim.authserver.entities.RSAKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface RSAKeyRepository extends JpaRepository<RSAKey, Long> {

    Optional<RSAKey> findByActiveTrue();

    Optional<RSAKey> findByKeyId(String keyId);

    // Custom method to delete inactive keys older than a certain time
    @Transactional
    @Modifying
    @Query("DELETE FROM RSAKey r WHERE r.active = false AND r.createdAt < :cutoffTime")
    int deleteByActiveFalseAndCreatedAtBefore(LocalDateTime cutoffTime);
}
