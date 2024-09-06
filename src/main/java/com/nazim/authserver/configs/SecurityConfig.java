package com.nazim.authserver.configs;

import com.nazim.authserver.security.CustomPermissionEvaluator;
import com.nazim.authserver.utils.JwtTokenUtil;
import com.nazim.authserver.entities.RSAKey;
import com.nazim.authserver.repositories.RSAKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtTokenUtil jwtTokenUtil;

    private final RSAKeyRepository rsaKeyRepository;

    private final CustomPermissionEvaluator customPermissionEvaluator;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // CSRF disabled for stateless sessions
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Stateless session management
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login", "/api/auth/change-password", "/api/auth/validate-token", "/api/auth/refresh-token", "/swagger-ui/**", "/v3/api-docs/**","/.well-known/jwks.json").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder())  // Configure JWT decoder explicitly
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())  // Link custom converter for roles
                        )
                );

        return http.build();
    }

    @Bean
    @DependsOn("keyRotationService")  // Ensure keys are initialized
    public JwtDecoder jwtDecoder() {
        RSAKey activeKey = rsaKeyRepository.findByActiveTrue().orElse(null);

        if (activeKey == null) {
            logger.error("No active RSA key found. Ensure the RSA keys are initialized.");
            throw new IllegalStateException("No active RSA key found. Make sure the RSA keys are initialized.");
        }

        PublicKey publicKey = jwtTokenUtil.getPublicKey(activeKey.getPublicKey());
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) publicKey).build();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // Custom JwtAuthenticationConverter to extract roles from JWT
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(this::extractAuthoritiesFromToken);
        return jwtAuthenticationConverter;
    }

    // Register the custom permission evaluator
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(customPermissionEvaluator);  // Set our custom evaluator
        return expressionHandler;
    }


    // Extract roles (authorities) from the token and convert them to GrantedAuthority
    private Collection<GrantedAuthority> extractAuthoritiesFromToken(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        return roles != null ? roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))  // Convert to GrantedAuthority
                .collect(Collectors.toList()) : List.of();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // Define the PasswordEncoder bean
    }
}
