package com.medseal.gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            Environment environment,
            Optional<DevBearerTokenFilter> devBearerTokenFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/health").permitAll()
                        .requestMatchers("/api/v1/**").authenticated()
                        .anyRequest().permitAll());

        if (environment.acceptsProfiles(Profiles.of("dev"))) {
            devBearerTokenFilter.ifPresent(filter ->
                    http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class));
        } else {
            http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        }

        return http.build();
    }

    @Bean
    @Profile("dev")
    DevBearerTokenFilter devBearerTokenFilter(
            @Value("${medseal.security.dev-token}") String devToken,
            @Value("${medseal.security.dev-principal}") String devPrincipal) {
        return new DevBearerTokenFilter(devToken, devPrincipal);
    }

    @Bean
    @Profile("!dev")
    JwtDecoder jwtDecoder(
            @Value("${medseal.security.jwt.issuer-uri:}") String issuerUri,
            @Value("${medseal.security.jwt.jwk-set-uri:}") String jwkSetUri) {
        if (StringUtils.hasText(jwkSetUri)) {
            return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        }
        if (StringUtils.hasText(issuerUri)) {
            return JwtDecoders.fromIssuerLocation(issuerUri);
        }
        return token -> {
            throw new JwtException("JWT issuer is not configured");
        };
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${medseal.security.cors.allowed-origins:}") String allowedOriginsCsv) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(parseAllowedOrigins(allowedOriginsCsv));
        configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Correlation-Id"));
        configuration.setExposedHeaders(List.of("X-Correlation-Id"));
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }

    private List<String> parseAllowedOrigins(String allowedOriginsCsv) {
        if (!StringUtils.hasText(allowedOriginsCsv)) {
            return List.of();
        }
        return Arrays.stream(allowedOriginsCsv.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }
}
