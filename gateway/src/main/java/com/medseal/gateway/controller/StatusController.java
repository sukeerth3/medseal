package com.medseal.gateway.controller;

import com.medseal.gateway.service.EnclaveService;
import com.medseal.gateway.model.HealthResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class StatusController {

    private final EnclaveService enclaveService;

    public StatusController(EnclaveService enclaveService) {
        this.enclaveService = enclaveService;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        HealthResponse enclaveHealth = enclaveService.health();
        boolean enclaveHealthy = enclaveHealth.isOk();

        Map<String, Object> body = Map.of(
                "status", enclaveHealthy ? "UP" : "DOWN",
                "gateway", "UP",
                "enclave", enclaveHealthy ? "UP" : "DOWN",
                "nsm", Boolean.TRUE.equals(enclaveHealth.nsmAvailable()) ? "UP" : "DOWN",
                "kms", Boolean.TRUE.equals(enclaveHealth.kmsReachable()) ? "UP" : "DOWN",
                "spacy", Boolean.TRUE.equals(enclaveHealth.spacyLoaded()) ? "UP" : "DOWN"
        );

        return ResponseEntity.status(enclaveHealthy ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE)
                .body(body);
    }
}
