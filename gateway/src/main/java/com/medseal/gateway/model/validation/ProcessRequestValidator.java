package com.medseal.gateway.model.validation;

import com.medseal.gateway.model.ProcessRequest;
import com.medseal.gateway.service.KmsBlobValidator;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.util.StringUtils;

import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class ProcessRequestValidator implements ConstraintValidator<ValidProcessRequest, ProcessRequest> {

    private static final int MAX_CIPHERTEXT_BYTES = 10 * 1024 * 1024;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BYTES = 16;
    private static final Pattern UUID_PATTERN =
            Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Set<String> REQUIRED_CONTEXT_KEYS = Set.of("jobId", "principal");
    private static final String DEFAULT_KMS_KEY_ALLOWLIST =
            "^(alias/[A-Za-z0-9/_+=,.@-]+|arn:aws[a-zA-Z-]*:kms:[a-z0-9-]+:[0-9]{12}:(key/[0-9a-fA-F-]{36}|alias/[A-Za-z0-9/_+=,.@-]+))$";

    @Value("${medseal.kms.key-id-allowlist-regex:" + DEFAULT_KMS_KEY_ALLOWLIST + "}")
    private String kmsKeyIdAllowlistRegex;

    @Autowired
    private KmsBlobValidator kmsBlobValidator;

    @Autowired
    private Environment environment;

    @Override
    public boolean isValid(ProcessRequest request, ConstraintValidatorContext context) {
        if (request == null) {
            return true;
        }

        ValidationErrors errors = new ValidationErrors(context);
        validateEncryptionContext(request, errors);

        validateBase64MaxBytes(
                request.ciphertextB64(),
                "ciphertextB64",
                "ciphertext must be valid base64 and decode to no more than 10MB",
                MAX_CIPHERTEXT_BYTES,
                errors);
        validateBase64ExactBytes(
                request.ivB64(),
                "ivB64",
                "IV must be valid base64 and decode to 12 bytes",
                GCM_IV_BYTES,
                errors);
        validateBase64ExactBytes(
                request.authTagB64(),
                "authTagB64",
                "auth tag must be valid base64 and decode to 16 bytes",
                GCM_TAG_BYTES,
                errors);

        if (StringUtils.hasText(request.kmsKeyId()) && !kmsKeyPattern().matcher(request.kmsKeyId()).matches()) {
            errors.add("kmsKeyId", "KMS key ID is not allowed");
        }

        if (StringUtils.hasText(request.encryptedDataKeyB64())) {
            Optional<String> dataKeyError = kmsBlobValidator.validateForProcess(request.encryptedDataKeyB64());
            dataKeyError.ifPresent(error -> errors.add("encryptedDataKeyB64", error));
        }

        return !errors.hasErrors();
    }

    private void validateEncryptionContext(ProcessRequest request, ValidationErrors errors) {
        Map<String, String> encryptionContext = request.encryptionContext();
        String contextJobId = encryptionContext == null ? null : encryptionContext.get("jobId");
        String contextPrincipal = encryptionContext == null ? null : encryptionContext.get("principal");
        String effectiveJobId = StringUtils.hasText(request.jobId()) ? request.jobId() : contextJobId;
        String effectivePrincipal = StringUtils.hasText(request.principal()) ? request.principal() : contextPrincipal;

        if (encryptionContext != null && !encryptionContext.isEmpty()) {
            if (!encryptionContext.keySet().equals(REQUIRED_CONTEXT_KEYS)) {
                errors.add("encryptionContext", "encryption context must contain only jobId and principal");
            }
            if (!StringUtils.hasText(contextJobId)) {
                errors.add("encryptionContext", "encryption context jobId is required");
            }
            if (!StringUtils.hasText(contextPrincipal)) {
                errors.add("encryptionContext", "encryption context principal is required");
            }
        }

        if (StringUtils.hasText(request.jobId())
                && StringUtils.hasText(contextJobId)
                && !request.jobId().equals(contextJobId)) {
            errors.add("encryptionContext", "encryption context jobId must match jobId");
        }

        if (StringUtils.hasText(request.principal())
                && StringUtils.hasText(contextPrincipal)
                && !request.principal().equals(contextPrincipal)) {
            errors.add("encryptionContext", "encryption context principal must match principal");
        }

        if (StringUtils.hasText(effectiveJobId) && !UUID_PATTERN.matcher(effectiveJobId).matches()) {
            errors.add("jobId", "jobId must be a UUID");
        }

        if (isProductionMode()) {
            if (!StringUtils.hasText(effectiveJobId)) {
                errors.add("jobId", "jobId is required in production");
            }
            if (!StringUtils.hasText(effectivePrincipal)) {
                errors.add("principal", "principal is required in production");
            }
        }
    }

    private void validateBase64MaxBytes(
            String value,
            String field,
            String message,
            int maxBytes,
            ValidationErrors errors) {
        if (!StringUtils.hasText(value)) {
            return;
        }

        Optional<byte[]> decoded = decode(value);
        if (decoded.isEmpty() || decoded.get().length > maxBytes) {
            errors.add(field, message);
        }
    }

    private void validateBase64ExactBytes(
            String value,
            String field,
            String message,
            int expectedBytes,
            ValidationErrors errors) {
        if (!StringUtils.hasText(value)) {
            return;
        }

        Optional<byte[]> decoded = decode(value);
        if (decoded.isEmpty() || decoded.get().length != expectedBytes) {
            errors.add(field, message);
        }
    }

    private Optional<byte[]> decode(String value) {
        try {
            return Optional.of(Base64.getDecoder().decode(value));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    private Pattern kmsKeyPattern() {
        try {
            return Pattern.compile(kmsKeyIdAllowlistRegex);
        } catch (PatternSyntaxException | NullPointerException ex) {
            return Pattern.compile(DEFAULT_KMS_KEY_ALLOWLIST);
        }
    }

    private boolean isProductionMode() {
        return environment != null
                && (environment.acceptsProfiles(Profiles.of("prod", "production"))
                || "production".equalsIgnoreCase(environment.getProperty("MEDSEAL_ENV")));
    }

    private static final class ValidationErrors {
        private final ConstraintValidatorContext context;
        private boolean hasErrors;

        private ValidationErrors(ConstraintValidatorContext context) {
            this.context = context;
        }

        private void add(String field, String message) {
            if (!hasErrors) {
                context.disableDefaultConstraintViolation();
            }
            hasErrors = true;
            context.buildConstraintViolationWithTemplate(message)
                    .addPropertyNode(field)
                    .addConstraintViolation();
        }

        private boolean hasErrors() {
            return hasErrors;
        }
    }
}
