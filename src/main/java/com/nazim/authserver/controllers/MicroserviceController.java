package com.nazim.authserver.controllers;

import com.nazim.authserver.entities.Microservice;
import com.nazim.authserver.responses.ApiResponse;
import com.nazim.authserver.services.MicroserviceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth/microservices")
@RequiredArgsConstructor
public class MicroserviceController {

    private final MicroserviceService microserviceService;

    // Register a new microservice
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Microservice>> registerMicroservice(@RequestBody Microservice microservice) {
        Microservice registeredMicroservice = microserviceService.registerMicroservice(microservice);
        return ResponseEntity.status(HttpStatus.CREATED).body(
                new ApiResponse<>("success", "Microservice registered successfully", registeredMicroservice)
        );
    }

    // View a specific microservice by ID
    @GetMapping("/{microserviceId}")
    public ResponseEntity<ApiResponse<Microservice>> viewMicroservice(@PathVariable Long microserviceId) {
        Microservice microservice = microserviceService.getMicroserviceById(microserviceId);
        return ResponseEntity.ok(new ApiResponse<>("success", "Microservice retrieved successfully", microservice));
    }

    // View all microservices
    @GetMapping
    public ResponseEntity<ApiResponse<List<Microservice>>> viewAllMicroservices() {
        List<Microservice> microservices = microserviceService.getAllMicroservices();
        return ResponseEntity.ok(new ApiResponse<>("success", "All microservices retrieved successfully", microservices));
    }

    // Update a specific microservice by ID
    @PutMapping("/{microserviceId}")
    public ResponseEntity<ApiResponse<Microservice>> updateMicroservice(
            @PathVariable Long microserviceId, @RequestBody Microservice microservice) {
        Microservice updatedMicroservice = microserviceService.updateMicroservice(microserviceId, microservice);
        return ResponseEntity.ok(new ApiResponse<>("success", "Microservice updated successfully", updatedMicroservice));
    }

    // Delete a specific microservice by ID
    @DeleteMapping("/{microserviceId}")
    public ResponseEntity<ApiResponse<String>> deleteMicroservice(@PathVariable Long microserviceId) {
        microserviceService.deleteMicroservice(microserviceId);
        return ResponseEntity.ok(new ApiResponse<>("success", "Microservice deleted successfully", null));
    }
}
