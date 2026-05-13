package com.medseal.gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

@Component
public class ProductionSecurityGuardrails implements ApplicationRunner {

    private final Environment environment;
    private final boolean tlsEnabled;
    private final boolean tcpFallbackEnabled;
    private final String jwtIssuerUri;
    private final String jwtJwkSetUri;

    public ProductionSecurityGuardrails(
            Environment environment,
            @Value("${server.ssl.enabled:false}") boolean tlsEnabled,
            @Value("${medseal.enclave.use-tcp-fallback:false}") boolean tcpFallbackEnabled,
            @Value("${medseal.security.jwt.issuer-uri:}") String jwtIssuerUri,
            @Value("${medseal.security.jwt.jwk-set-uri:}") String jwtJwkSetUri) {
        this.environment = environment;
        this.tlsEnabled = tlsEnabled;
        this.tcpFallbackEnabled = tcpFallbackEnabled;
        this.jwtIssuerUri = jwtIssuerUri;
        this.jwtJwkSetUri = jwtJwkSetUri;
    }

    @Override
    public void run(ApplicationArguments args) {
        boolean devProfile = environment.acceptsProfiles(Profiles.of("dev"));
        List<String> violations = validate(
                devProfile,
                tlsEnabled,
                tcpFallbackEnabled,
                jwtIssuerUri,
                jwtJwkSetUri);
        if (!violations.isEmpty()) {
            throw new IllegalStateException("Unsafe gateway configuration: " + String.join("; ", violations));
        }
    }

    static List<String> validate(
            boolean devProfile,
            boolean tlsEnabled,
            boolean tcpFallbackEnabled,
            String jwtIssuerUri,
            String jwtJwkSetUri) {
        if (devProfile) {
            return List.of();
        }

        List<String> violations = new ArrayList<>();
        if (!tlsEnabled) {
            violations.add("server.ssl.enabled must be true outside the dev profile");
        }
        if (tcpFallbackEnabled) {
            violations.add("medseal.enclave.use-tcp-fallback must be false outside the dev profile");
        }
        if (!StringUtils.hasText(jwtIssuerUri) && !StringUtils.hasText(jwtJwkSetUri)) {
            violations.add("configure MEDSEAL_JWT_ISSUER_URI or MEDSEAL_JWT_JWK_SET_URI outside the dev profile");
        }
        return List.copyOf(violations);
    }
}
