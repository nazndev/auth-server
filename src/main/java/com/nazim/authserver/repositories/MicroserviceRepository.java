package com.nazim.authserver.repositories;

import com.nazim.authserver.entities.Microservice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MicroserviceRepository extends JpaRepository<Microservice, Long> {
    Optional<Microservice> findByName(String name);
}

