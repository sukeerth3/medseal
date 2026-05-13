package com.medseal.gateway.service;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Base64;
import java.util.Optional;

@Service
public class KmsBlobValidator {

    private static final int RAW_AES_256_KEY_BYTES = 32;

    private final Environment environment;

    public KmsBlobValidator(Environment environment) {
        this.environment = environment;
    }

    public Optional<String> validateForProcess(String encryptedDataKeyB64) {
        if (!StringUtils.hasText(encryptedDataKeyB64)) {
            return Optional.empty();
        }

        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(encryptedDataKeyB64);
        } catch (IllegalArgumentException ex) {
            return Optional.of("encrypted data key must be valid base64");
        }

        if (isProductionProfile() && decoded.length == RAW_AES_256_KEY_BYTES) {
            return Optional.of("encrypted data key must be a KMS ciphertext blob, not a raw AES-256 key");
        }

        return Optional.empty();
    }

    private boolean isProductionProfile() {
        return environment.acceptsProfiles(Profiles.of("prod", "production"))
                || "production".equalsIgnoreCase(environment.getProperty("MEDSEAL_ENV"));
    }
}
