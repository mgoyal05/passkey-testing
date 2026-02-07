package com.tara.passkey.security;

import jakarta.servlet.http.HttpSession;
import java.util.function.Supplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

@Configuration
public class SecurityConfig {
    private final boolean bypassPreAuth;

    public SecurityConfig(@Value("${app.dev.bypass-preauth:false}") boolean bypassPreAuth) {
        this.bypassPreAuth = bypassPreAuth;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/crypto/server-pubkey", "/css/**", "/js/**").permitAll()
                        .requestMatchers("/api/otp/**").permitAll()
                        .requestMatchers("/passkey/enroll", "/api/webauthn/register/**").access(preAuth())
                        .requestMatchers("/pay", "/pay/**", "/api/payments/**").access(authenticated())
                        .anyRequest().permitAll()
                );
        return http.build();
    }

    private AuthorizationManager<RequestAuthorizationContext> preAuth() {
        return (Supplier<org.springframework.security.core.Authentication> authentication, RequestAuthorizationContext context) -> {
            HttpSession session = context.getRequest().getSession(false);
            boolean allowed = bypassPreAuth || (session != null && Boolean.TRUE.equals(session.getAttribute(SessionConstants.PRE_AUTH)));
            return new AuthorizationDecision(allowed);
        };
    }

    private AuthorizationManager<RequestAuthorizationContext> authenticated() {
        return (Supplier<org.springframework.security.core.Authentication> authentication, RequestAuthorizationContext context) -> {
            HttpSession session = context.getRequest().getSession(false);
            boolean allowed = session != null && session.getAttribute(SessionConstants.AUTHENTICATED_USER) != null;
            return new AuthorizationDecision(allowed);
        };
    }
}
