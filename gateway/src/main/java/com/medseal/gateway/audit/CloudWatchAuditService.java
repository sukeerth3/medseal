package com.medseal.gateway.audit;

import com.medseal.gateway.security.RequestCorrelationFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

/**
 * CloudWatch-backed audit logging.
 * <p>
 * Uses structured logging (SLF4J) which is picked up by the
 * CloudWatch agent. In production, configure CloudWatch Logs
 * Insights for querying audit events.
 */
@Service
public class CloudWatchAuditService implements AuditService {

    private static final Logger audit = LoggerFactory.getLogger("medseal.audit");

    @Override
    public void logJobCreated(String jobId, String kmsKeyId, long requestSizeBytes) {
        audit.info("event=JOB_CREATED jobId={} principal={} source_ip={} request_size_bytes={} kmsKeyId={} status=SUBMITTED correlation_id={}",
                jobId, principal(), sourceIp(), requestSizeBytes, kmsKeyId, correlationId());
    }

    @Override
    public void logJobSubmitted(String jobId, String kmsKeyId, long requestSizeBytes) {
        audit.info("event=JOB_SUBMITTED jobId={} principal={} source_ip={} request_size_bytes={} kmsKeyId={} status=PROCESSING correlation_id={}",
                jobId, principal(), sourceIp(), requestSizeBytes, kmsKeyId, correlationId());
    }

    @Override
    public void logJobCompleted(
            String jobId,
            String attestationHash,
            int processingTimeMs,
            String kmsKeyId,
            String s3Key) {
        audit.info("event=JOB_COMPLETED jobId={} principal={} source_ip={} kmsKeyId={} attestation_digest={} s3_key={} processing_time_ms={} status=COMPLETED correlation_id={}",
                jobId, principal(), sourceIp(), kmsKeyId, attestationHash, s3Key, processingTimeMs, correlationId());
    }

    @Override
    public void logJobFailed(String jobId, String reason, String kmsKeyId) {
        audit.warn("event=JOB_FAILED jobId={} principal={} source_ip={} kmsKeyId={} status=FAILED reason={} correlation_id={}",
                jobId, principal(), sourceIp(), kmsKeyId, sanitize(reason), correlationId());
    }

    private String principal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "anonymous";
        }
        return sanitize(authentication.getName());
    }

    private String sourceIp() {
        return currentRequest()
                .map(request -> {
                    String forwardedFor = request.getHeader("X-Forwarded-For");
                    if (forwardedFor != null && !forwardedFor.isBlank()) {
                        return sanitize(forwardedFor.split(",")[0].trim());
                    }
                    return sanitize(request.getRemoteAddr());
                })
                .orElse("unknown");
    }

    private long requestSize() {
        return currentRequest()
                .map(HttpServletRequest::getContentLengthLong)
                .filter(length -> length >= 0)
                .orElse(0L);
    }

    private Optional<HttpServletRequest> currentRequest() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return Optional.of(attributes.getRequest());
        }
        return Optional.empty();
    }

    private String correlationId() {
        String value = MDC.get(RequestCorrelationFilter.MDC_KEY);
        return value == null ? "unknown" : sanitize(value);
    }

    private String sanitize(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.replaceAll("\\s+", "_");
    }
}
