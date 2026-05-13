package com.medseal.gateway.model.validation;

import com.medseal.gateway.model.ProcessRequest;
import com.medseal.gateway.service.KmsBlobValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProcessRequestValidatorTest {

    private static final String JOB_ID = "11111111-1111-4111-8111-111111111111";
    private static final String PRINCIPAL = "arn:aws:iam::111122223333:user/tester";

    @Test
    void productionRejectsMissingEncryptionContextIdentity() {
        ProcessRequestValidator validator = validator("production");

        assertThat(validator.isValid(request(null, null, null), constraintContext()))
                .isFalse();
    }

    @Test
    void rejectsContextThatDoesNotMatchTopLevelFields() {
        ProcessRequestValidator validator = validator("production");

        ProcessRequest request = request(
                JOB_ID,
                PRINCIPAL,
                Map.of("jobId", "22222222-2222-4222-8222-222222222222", "principal", PRINCIPAL));

        assertThat(validator.isValid(request, constraintContext()))
                .isFalse();
    }

    @Test
    void acceptsCanonicalEncryptionContext() {
        ProcessRequestValidator validator = validator("production");

        ProcessRequest request = request(
                JOB_ID,
                PRINCIPAL,
                Map.of("jobId", JOB_ID, "principal", PRINCIPAL));

        assertThat(validator.isValid(request, constraintContext()))
                .isTrue();
    }

    @Test
    void acceptsFullEncryptionContextWithoutTopLevelIdentity() {
        ProcessRequestValidator validator = validator("production");

        ProcessRequest request = request(
                null,
                null,
                Map.of("jobId", JOB_ID, "principal", PRINCIPAL));

        assertThat(validator.isValid(request, constraintContext()))
                .isTrue();
    }

    private ProcessRequestValidator validator(String medsealEnv) {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("MEDSEAL_ENV", medsealEnv);
        ProcessRequestValidator validator = new ProcessRequestValidator();
        ReflectionTestUtils.setField(validator, "environment", environment);
        ReflectionTestUtils.setField(validator, "kmsBlobValidator", new KmsBlobValidator(environment));
        return validator;
    }

    private ProcessRequest request(String jobId, String principal, Map<String, String> encryptionContext) {
        return new ProcessRequest(
                jobId,
                principal,
                encryptionContext,
                b64(new byte[]{1, 2, 3}),
                b64(new byte[64]),
                b64(new byte[12]),
                b64(new byte[16]),
                "alias/medseal-master");
    }

    private String b64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    private ConstraintValidatorContext constraintContext() {
        ConstraintValidatorContext context = mock(ConstraintValidatorContext.class);
        ConstraintValidatorContext.ConstraintViolationBuilder builder =
                mock(ConstraintValidatorContext.ConstraintViolationBuilder.class);
        ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext node =
                mock(ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext.class);
        when(context.buildConstraintViolationWithTemplate(anyString())).thenReturn(builder);
        when(builder.addPropertyNode(anyString())).thenReturn(node);
        when(node.addConstraintViolation()).thenReturn(context);
        return context;
    }
}
