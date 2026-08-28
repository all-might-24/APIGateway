package com.ecommerceproject.apigateway.config;

import com.ecommerceproject.apigateway.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity serverHttpSecurity,
            JwtAuthenticationFilter jwtAuthenticationFilter) {

        return serverHttpSecurity
                .csrf(csrfSpec -> csrfSpec.disable())

                .addFilterAt(
                        jwtAuthenticationFilter,
                        SecurityWebFiltersOrder.AUTHENTICATION
                )

                .authorizeExchange(exchange -> exchange
                        .pathMatchers(
                                "/auth/signup",
                                "/auth/login",
                                "/auth/validate-token",
                                "/actuator/health",
                                "/actuator/info",
                                "/actuator/metrics/**",
                                "/fallback/products",
                                "/actuator/gateway/routes"
                        ).permitAll()
                        .pathMatchers(HttpMethod.GET, "/products/**").permitAll()
                        .anyExchange().authenticated()
                )


                .build();
    }
}
