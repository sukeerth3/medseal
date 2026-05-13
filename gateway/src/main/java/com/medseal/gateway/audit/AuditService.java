package com.medseal.gateway.audit;

/**
 * Audit logging contract.
 * <p>
 * Audit events record metadata only. PHI must never be written to audit logs.
 */
public interface AuditService {

    void logJobCreated(String jobId, String kmsKeyId, long requestSizeBytes);

    void logJobSubmitted(String jobId, String kmsKeyId, long requestSizeBytes);

    void logJobCompleted(String jobId, String attestationHash, int processingTimeMs, String kmsKeyId, String s3Key);

    void logJobFailed(String jobId, String reason, String kmsKeyId);
}
