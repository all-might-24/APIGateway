package com.ecommerceproject.apigateway.config;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Configuration
public class SecretKeyConfig {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Bean
    public SecretKey getSecretKey() {
        return Keys
                .hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }




}
