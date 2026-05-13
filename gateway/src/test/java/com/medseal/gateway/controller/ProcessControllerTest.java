package com.medseal.gateway.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medseal.gateway.audit.AuditService;
import com.medseal.gateway.model.JobStatus;
import com.medseal.gateway.model.ProcessRequest;
import com.medseal.gateway.service.EnclaveService;
import com.medseal.gateway.service.JobService;
import com.medseal.gateway.service.StorageService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ProcessControllerTest {

    private static final String JOB_ID = "11111111-1111-4111-8111-111111111111";
    private static final String AUTH_PRINCIPAL = "dev-user";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final EnclaveService enclaveService = mock(EnclaveService.class);
    private final JobService jobService = mock(JobService.class);
    private final StorageService storageService = mock(StorageService.class);
    private final AuditService auditService = mock(AuditService.class);

    @Test
    void rejectsContextPrincipalThatDoesNotMatchAuthenticatedPrincipal() {
        ProcessController controller = controller();
        ProcessRequest request = request(
                "arn:aws:iam::111122223333:user/attacker",
                Map.of(
                        "jobId", JOB_ID,
                        "principal", "arn:aws:iam::111122223333:user/attacker"));

        assertThatThrownBy(() -> controller.process(request, auth()))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("authenticated principal");

        verifyNoInteractions(jobService, enclaveService, storageService, auditService);
    }

    @Test
    void forwardsAuthenticatedPrincipalAsTheBoundEncryptionContext() throws Exception {
        ProcessController controller = controller();
        ProcessRequest request = request(
                AUTH_PRINCIPAL,
                Map.of("jobId", JOB_ID, "principal", AUTH_PRINCIPAL));
        when(jobService.createJob(JOB_ID, AUTH_PRINCIPAL))
                .thenReturn(JobStatus.submitted(JOB_ID, AUTH_PRINCIPAL));

        ArgumentCaptor<String> payload = ArgumentCaptor.forClass(String.class);
        when(enclaveService.process(eq(JOB_ID), payload.capture()))
                .thenReturn(enclaveCompletedResponse());
        when(storageService.store(eq(JOB_ID), any()))
                .thenReturn("results/" + JOB_ID + ".json");

        var response = controller.process(request, auth());

        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().encryptionContext())
                .containsEntry("jobId", JOB_ID)
                .containsEntry("principal", AUTH_PRINCIPAL);

        Map<String, Object> enclavePayload = objectMapper.readValue(
                payload.getValue(),
                new TypeReference<>() {
                });
        assertThat(enclavePayload)
                .containsEntry("job_id", JOB_ID)
                .containsEntry("principal", AUTH_PRINCIPAL);
        Map<?, ?> context = (Map<?, ?>) enclavePayload.get("encryption_context");
        assertThat(context.get("jobId")).isEqualTo(JOB_ID);
        assertThat(context.get("principal")).isEqualTo(AUTH_PRINCIPAL);

        verify(jobService).createJob(JOB_ID, AUTH_PRINCIPAL);
    }

    private ProcessController controller() {
        return new ProcessController(
                enclaveService,
                jobService,
                storageService,
                auditService,
                objectMapper,
                StaticCredentialsProvider.create(
                        AwsSessionCredentials.create("AKIA_TEST", "secret", "token")));
    }

    private UsernamePasswordAuthenticationToken auth() {
        return new UsernamePasswordAuthenticationToken(AUTH_PRINCIPAL, "token");
    }

    private ProcessRequest request(String principal, Map<String, String> context) {
        return new ProcessRequest(
                JOB_ID,
                principal,
                context,
                b64(new byte[]{1, 2, 3}),
                b64(new byte[64]),
                b64(new byte[12]),
                b64(new byte[16]),
                "alias/medseal-master");
    }

    private String enclaveCompletedResponse() throws Exception {
        return objectMapper.writeValueAsString(Map.of(
                "job_id", JOB_ID,
                "status", "COMPLETED",
                "encrypted_result_b64", b64(new byte[]{9, 8, 7}),
                "encrypted_data_key_b64", b64(new byte[64]),
                "iv_b64", b64(new byte[12]),
                "auth_tag_b64", b64(new byte[16]),
                "attestation_hash", "attestation",
                "processing_time_ms", 42,
                "encryption_context", Map.of("jobId", JOB_ID, "principal", AUTH_PRINCIPAL)));
    }

    private String b64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }
}
