package com.medseal.gateway.model;

import com.fasterxml.jackson.annotation.JsonAlias;

import java.util.Map;

/**
 * Encrypted response from the enclave, forwarded to the client.
 */
public record ProcessResponse(
        @JsonAlias("job_id")
        String jobId,
        String status,
        @JsonAlias("encrypted_result_b64")
        String encryptedResultB64,
        @JsonAlias("encrypted_data_key_b64")
        String encryptedDataKeyB64,
        @JsonAlias("iv_b64")
        String ivB64,
        @JsonAlias("auth_tag_b64")
        String authTagB64,
        @JsonAlias("attestation_hash")
        String attestationHash,
        @JsonAlias("processing_time_ms")
        int processingTimeMs,
        @JsonAlias("encryption_context")
        Map<String, String> encryptionContext,
        @JsonAlias("error_message")
        String errorMessage
) {
}
