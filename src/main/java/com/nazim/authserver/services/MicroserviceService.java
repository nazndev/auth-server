package com.nazim.authserver.services;

import com.nazim.authserver.entities.Microservice;
import com.nazim.authserver.repositories.MicroserviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class MicroserviceService {

    private final MicroserviceRepository microserviceRepository;

    // Register a new microservice
    public Microservice registerMicroservice(Microservice microservice) {
        return microserviceRepository.save(microservice);
    }

    // Get a specific microservice by ID
    public Microservice getMicroserviceById(Long microserviceId) {
        return microserviceRepository.findById(microserviceId)
                .orElseThrow(() -> new RuntimeException("Microservice not found"));
    }

    // Get all microservices
    public List<Microservice> getAllMicroservices() {
        return microserviceRepository.findAll();
    }

    // Update a specific microservice
    public Microservice updateMicroservice(Long microserviceId, Microservice microserviceUpdates) {
        Microservice microservice = getMicroserviceById(microserviceId);
        microservice.setName(microserviceUpdates.getName());
        microservice.setDescription(microserviceUpdates.getDescription());
        return microserviceRepository.save(microservice);
    }

    // Delete a microservice by ID
    public void deleteMicroservice(Long microserviceId) {
        Microservice microservice = getMicroserviceById(microserviceId);
        microserviceRepository.delete(microservice);
    }
}
