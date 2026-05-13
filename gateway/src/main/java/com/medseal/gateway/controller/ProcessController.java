package com.medseal.gateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medseal.gateway.audit.AuditService;
import com.medseal.gateway.exception.EnclaveException;
import com.medseal.gateway.model.JobStatus;
import com.medseal.gateway.model.ProcessRequest;
import com.medseal.gateway.model.ProcessResponse;
import com.medseal.gateway.service.EnclaveService;
import com.medseal.gateway.service.JobService;
import com.medseal.gateway.service.StorageService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

/**
 * REST controller for medical record processing.
 * <p>
 * Endpoints:
 * - POST /api/v1/process: submit encrypted record for processing
 * - GET /api/v1/jobs/{jobId}: get job status
 * - GET /api/v1/jobs/{jobId}/result: retrieve encrypted result
 * <p>
 * The controller handles auth, validation, job metadata, and storage while
 * forwarding encrypted payloads to the enclave.
 */
@RestController
@RequestMapping("/api/v1")
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:5173"})
public class ProcessController {

    private static final Logger log = LoggerFactory.getLogger(ProcessController.class);

    private final EnclaveService enclaveService;
    private final JobService jobService;
    private final StorageService storageService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;
    private final AwsCredentialsProvider credentialsProvider;

    public ProcessController(
            EnclaveService enclaveService,
            JobService jobService,
            StorageService storageService,
            AuditService auditService,
            ObjectMapper objectMapper,
            AwsCredentialsProvider credentialsProvider) {
        this.enclaveService = enclaveService;
        this.jobService = jobService;
        this.storageService = storageService;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
        this.credentialsProvider = credentialsProvider;
    }

    /**
     * Submit an encrypted medical record for confidential processing.
     */
    @PostMapping("/process")
    public ResponseEntity<ProcessResponse> process(
            @Valid @RequestBody ProcessRequest request,
            Authentication authentication) {
        String principal = principalName(authentication);
        requireRequestPrincipalMatchesAuthentication(request, principal);
        long requestSizeBytes = requestSizeBytes(request);

        String requestedJobId = effectiveJobId(request);
        JobStatus job = StringUtils.hasText(requestedJobId)
                ? jobService.createJob(requestedJobId, principal)
                : jobService.createJob(principal);
        String jobId = job.jobId();
        Map<String, String> encryptionContext = new TreeMap<>(Map.of(
                "jobId", jobId,
                "principal", principal
        ));

        auditService.logJobCreated(jobId, request.kmsKeyId(), requestSizeBytes);

        try {
            // The enclave request schema uses snake_case fields.
            AwsSessionCredentials enclaveCredentials = resolveSessionCredentials();
            Map<String, Object> enclaveEnvelope = new LinkedHashMap<>();
            enclaveEnvelope.put("job_id", jobId);
            enclaveEnvelope.put("principal", principal);
            enclaveEnvelope.put("encryption_context", encryptionContext);
            enclaveEnvelope.put("ciphertext_b64", request.ciphertextB64());
            enclaveEnvelope.put("encrypted_data_key_b64", request.encryptedDataKeyB64());
            enclaveEnvelope.put("iv_b64", request.ivB64());
            enclaveEnvelope.put("auth_tag_b64", request.authTagB64());
            enclaveEnvelope.put("kms_key_id", request.kmsKeyId());
            enclaveEnvelope.put("aws_access_key_id", enclaveCredentials.accessKeyId());
            enclaveEnvelope.put("aws_secret_access_key", enclaveCredentials.secretAccessKey());
            enclaveEnvelope.put("aws_session_token", enclaveCredentials.sessionToken());
            String enclavePayload = objectMapper.writeValueAsString(enclaveEnvelope);

            auditService.logJobSubmitted(jobId, request.kmsKeyId(), requestSizeBytes);
            jobService.updateJob(job.withStatus(JobStatus.Status.PROCESSING.name()));

            String enclaveResponse = enclaveService.process(jobId, enclavePayload);
            ProcessResponse response = objectMapper.readValue(enclaveResponse, ProcessResponse.class);

            if ("COMPLETED".equals(response.status())) {
                String s3Key = storageService.store(jobId, enclaveResponse.getBytes(StandardCharsets.UTF_8));
                jobService.updateJob(job.completed(response.attestationHash(), response.processingTimeMs()));
                auditService.logJobCompleted(
                        jobId,
                        response.attestationHash(),
                        response.processingTimeMs(),
                        request.kmsKeyId(),
                        s3Key);
            } else {
                String failureReason = response.errorMessage() == null || response.errorMessage().isBlank()
                        ? "Enclave returned non-completed status"
                        : response.errorMessage();
                jobService.updateJob(job.failed(failureReason));
                auditService.logJobFailed(jobId, failureReason, request.kmsKeyId());
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("[{}] Processing failed: {}", jobId, e.getMessage());
            jobService.updateJob(job.failed(e.getMessage()));
            auditService.logJobFailed(jobId, e.getMessage(), request.kmsKeyId());

            if (e instanceof EnclaveException enclaveException) {
                throw enclaveException;
            }
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR, "Processing failed", e);
        }
    }

    /**
     * Get job status.
     */
    @GetMapping("/jobs/{jobId}")
    public ResponseEntity<JobStatus> getJobStatus(@PathVariable String jobId, Authentication authentication) {
        String principal = principalName(authentication);
        return jobService.getJob(jobId)
                .filter(job -> isOwner(job, principal))
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * List recent jobs for the authenticated principal.
     */
    @GetMapping("/jobs")
    public ResponseEntity<List<JobStatus>> listJobs(
            @RequestParam(defaultValue = "20") int limit,
            Authentication authentication) {
        String principal = principalName(authentication);
        int safeLimit = Math.max(1, Math.min(limit, 50));
        return ResponseEntity.ok(jobService.listRecentJobs(principal, safeLimit));
    }

    /**
     * Retrieve encrypted result for a completed job.
     */
    @GetMapping("/jobs/{jobId}/result")
    public ResponseEntity<byte[]> getResult(@PathVariable String jobId, Authentication authentication) {
        String principal = principalName(authentication);
        var job = jobService.getJob(jobId);
        if (job.isEmpty() || !isOwner(job.get(), principal)) {
            return ResponseEntity.notFound().build();
        }
        if (!"COMPLETED".equals(job.get().status())) {
            return ResponseEntity.badRequest().build();
        }

        byte[] encryptedResult = storageService.retrieve(jobId);
        return ResponseEntity.ok(encryptedResult);
    }

    private String principalName(Authentication authentication) {
        if (authentication == null || authentication.getName() == null || authentication.getName().isBlank()) {
            return "anonymous";
        }
        return authentication.getName();
    }

    private boolean isOwner(JobStatus job, String principal) {
        return principal.equals(job.ownerPrincipal());
    }

    private long requestSizeBytes(ProcessRequest request) {
        try {
            return objectMapper.writeValueAsBytes(request).length;
        } catch (Exception ex) {
            return 0L;
        }
    }

    private String effectiveJobId(ProcessRequest request) {
        if (StringUtils.hasText(request.jobId())) {
            return request.jobId();
        }
        return request.contextJobId();
    }

    private void requireRequestPrincipalMatchesAuthentication(ProcessRequest request, String authenticatedPrincipal) {
        String requestedPrincipal = null;
        if (StringUtils.hasText(request.principal())) {
            requestedPrincipal = request.principal();
        }
        if (StringUtils.hasText(request.contextPrincipal())) {
            if (StringUtils.hasText(requestedPrincipal) && !requestedPrincipal.equals(request.contextPrincipal())) {
                throw new ResponseStatusException(
                        BAD_REQUEST,
                        "encryption context principal must match principal");
            }
            requestedPrincipal = request.contextPrincipal();
        }
        if (StringUtils.hasText(requestedPrincipal) && !authenticatedPrincipal.equals(requestedPrincipal)) {
            throw new ResponseStatusException(
                    BAD_REQUEST,
                    "encryption context principal must match authenticated principal");
        }
    }

    private AwsSessionCredentials resolveSessionCredentials() {
        AwsCredentials credentials = credentialsProvider.resolveCredentials();
        if (credentials instanceof AwsSessionCredentials sessionCredentials) {
            return sessionCredentials;
        }
        throw new IllegalStateException("EC2 instance profile session credentials are required for enclave KMS");
    }
}
