package com.medseal.gateway.model;

import java.time.Instant;

/**
 * Job tracking metadata stored in DynamoDB.
 */
public record JobStatus(
        String jobId,
        String status,
        Instant createdAt,
        Instant updatedAt,
        String attestationHash,
        Integer processingTimeMs,
        String errorMessage,
        String ownerPrincipal
) {

    public enum Status {
        SUBMITTED,
        PROCESSING,
        COMPLETED,
        FAILED
    }

    public static JobStatus submitted(String jobId) {
        return submitted(jobId, null);
    }

    public static JobStatus submitted(String jobId, String ownerPrincipal) {
        Instant now = Instant.now();
        return new JobStatus(jobId, Status.SUBMITTED.name(), now, now, null, null, null, ownerPrincipal);
    }

    public JobStatus withStatus(String newStatus) {
        return new JobStatus(jobId, newStatus, createdAt, Instant.now(),
                attestationHash, processingTimeMs, errorMessage, ownerPrincipal);
    }

    public JobStatus completed(String attestationHash, int processingTimeMs) {
        return new JobStatus(jobId, Status.COMPLETED.name(), createdAt, Instant.now(),
                attestationHash, processingTimeMs, null, ownerPrincipal);
    }

    public JobStatus failed(String error) {
        return new JobStatus(jobId, Status.FAILED.name(), createdAt, Instant.now(),
                attestationHash, processingTimeMs, error, ownerPrincipal);
    }
}
