package com.medseal.gateway.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

class EnclaveServiceImplHealthTest {

    @Test
    void failedEnclaveResponseDoesNotMakeHealthUp() {
        EnclaveServiceImpl service = new EnclaveServiceImpl(new ObjectMapper()) {
            @Override
            public String process(String jobId, String jsonPayload) {
                return "{\"status\":\"FAILED\"}";
            }
        };

        assertFalse(service.isHealthy());
    }

    @Test
    void unhealthyDependencyFlagsDoNotMakeHealthUp() {
        EnclaveServiceImpl service = new EnclaveServiceImpl(new ObjectMapper()) {
            @Override
            public String process(String jobId, String jsonPayload) {
                return "{\"type\":\"health\",\"status\":\"OK\",\"nsm_available\":true,\"kms_reachable\":false,\"spacy_loaded\":true}";
            }
        };

        assertFalse(service.isHealthy());
    }
}
