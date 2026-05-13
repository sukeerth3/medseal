package com.medseal.gateway.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProductionSecurityGuardrailsTest {

    @Test
    void devProfileBypassesProductionRequirements() {
        assertThat(ProductionSecurityGuardrails.validate(true, false, true, "", ""))
                .isEmpty();
    }

    @Test
    void productionRequiresTlsJwtAndRealVsockMode() {
        assertThat(ProductionSecurityGuardrails.validate(false, false, true, "", ""))
                .containsExactly(
                        "server.ssl.enabled must be true outside the dev profile",
                        "medseal.enclave.use-tcp-fallback must be false outside the dev profile",
                        "configure MEDSEAL_JWT_ISSUER_URI or MEDSEAL_JWT_JWK_SET_URI outside the dev profile");
    }

    @Test
    void productionAcceptsJwtIssuerUri() {
        assertThat(ProductionSecurityGuardrails.validate(
                false,
                true,
                false,
                "https://issuer.example.com",
                ""))
                .isEmpty();
    }

    @Test
    void productionAcceptsJwkSetUri() {
        assertThat(ProductionSecurityGuardrails.validate(
                false,
                true,
                false,
                "",
                "https://issuer.example.com/.well-known/jwks.json"))
                .isEmpty();
    }
}
