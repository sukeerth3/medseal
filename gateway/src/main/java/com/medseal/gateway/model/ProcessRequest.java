package com.medseal.gateway.model;

import com.medseal.gateway.model.validation.ValidProcessRequest;
import jakarta.validation.constraints.NotBlank;

import java.util.Map;

/**
 * Incoming encrypted payload from the client.
 * <p>
 * All payload fields are Base64-encoded ciphertext. The gateway validates
 * envelope shape and size, but does not decrypt or inspect PHI contents.
 */
@ValidProcessRequest
public record ProcessRequest(

        String jobId,

        String principal,

        Map<String, String> encryptionContext,

        @NotBlank(message = "ciphertext is required")
        String ciphertextB64,

        @NotBlank(message = "encrypted data key is required")
        String encryptedDataKeyB64,

        @NotBlank(message = "IV is required")
        String ivB64,

        @NotBlank(message = "auth tag is required")
        String authTagB64,

        @NotBlank(message = "KMS key ID is required")
        String kmsKeyId
) {
    public String contextJobId() {
        return contextValue("jobId");
    }

    public String contextPrincipal() {
        return contextValue("principal");
    }

    private String contextValue(String key) {
        if (encryptionContext == null) {
            return null;
        }
        return encryptionContext.get(key);
    }
}
