package com.medseal.gateway.model;

import com.fasterxml.jackson.annotation.JsonAlias;

public record HealthResponse(
        String type,
        String status,
        @JsonAlias("nsm_available")
        Boolean nsmAvailable,
        @JsonAlias("kms_reachable")
        Boolean kmsReachable,
        @JsonAlias("spacy_loaded")
        Boolean spacyLoaded
) {
    public boolean isOk() {
        return "OK".equals(status)
                && Boolean.TRUE.equals(nsmAvailable)
                && Boolean.TRUE.equals(kmsReachable)
                && Boolean.TRUE.equals(spacyLoaded);
    }

    public static HealthResponse down() {
        return new HealthResponse("health", "DOWN", false, false, false);
    }
}
