package com.medseal.gateway.service;

import com.medseal.gateway.model.HealthResponse;

/**
 * Enclave communication contract.
 * <p>
 * The gateway sends encrypted payloads to the enclave and receives encrypted
 * results. It never inspects payload contents.
 */
public interface EnclaveService {

    /**
     * Send an encrypted payload to the enclave for processing.
     *
     * @param jobId       Unique job identifier
     * @param jsonPayload JSON-serialized encrypted request
     * @return JSON-serialized encrypted response from the enclave
     * @throws EnclaveUnavailableException if the enclave is not reachable
     */
    String process(String jobId, String jsonPayload);

    /**
     * Check if the enclave is healthy and accepting connections.
     */
    boolean isHealthy();

    /**
     * Return the latest structured enclave health probe.
     */
    HealthResponse health();
}
