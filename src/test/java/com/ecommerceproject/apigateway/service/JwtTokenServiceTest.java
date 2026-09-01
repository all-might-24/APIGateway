package com.ecommerceproject.apigateway.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenServiceTest {

    private SecretKey secretKey;

    private JwtTokenService jwtTokenService;


    @BeforeEach
    void setUp() {

        String secret =
                "this-is-a-test-secret-key-with-at-least-32-bytes";

        secretKey = Keys.hmacShaKeyFor(
                secret.getBytes(StandardCharsets.UTF_8)
        );

        jwtTokenService =
                new JwtTokenService(secretKey);
    }


    /*
     * =========================================================
     * VALIDATE TOKEN
     * =========================================================
     */

    @Test
    void validateToken_withValidToken_shouldReturnTrue() {

        String token = createToken(
                secretKey,
                10L,
                List.of("USER")
        );

        boolean result =
                jwtTokenService.validateToken(token);

        assertTrue(result);
    }


    @Test
    void validateToken_withMalformedToken_shouldReturnFalse() {

        boolean result =
                jwtTokenService.validateToken(
                        "this-is-not-a-jwt"
                );

        assertFalse(result);
    }


    @Test
    void validateToken_withEmptyToken_shouldReturnFalse() {

        boolean result =
                jwtTokenService.validateToken("");

        assertFalse(result);
    }


    @Test
    void validateToken_withTokenSignedUsingDifferentKey_shouldReturnFalse() {

        SecretKey differentKey =
                Keys.hmacShaKeyFor(
                        "this-is-a-completely-different-test-secret-key-123"
                                .getBytes(StandardCharsets.UTF_8)
                );

        String token = createToken(
                differentKey,
                10L,
                List.of("USER")
        );

        boolean result =
                jwtTokenService.validateToken(token);

        assertFalse(result);
    }


    /*
     * =========================================================
     * EXTRACT CLAIMS
     * =========================================================
     */

    @Test
    void extractClaims_shouldReturnUserId() {

        String token = createToken(
                secretKey,
                25L,
                List.of("USER")
        );

        Claims claims =
                jwtTokenService.extractClaims(token);

        Long userId =
                claims.get(
                        "userId",
                        Long.class
                );

        assertEquals(
                25L,
                userId
        );
    }


    @Test
    void extractClaims_shouldReturnSingleRole() {

        String token = createToken(
                secretKey,
                25L,
                List.of("USER")
        );

        Claims claims =
                jwtTokenService.extractClaims(token);

        List<?> roles =
                claims.get(
                        "scope",
                        List.class
                );

        assertNotNull(roles);

        assertEquals(
                List.of("USER"),
                roles
        );
    }


    @Test
    void extractClaims_shouldReturnMultipleRoles() {

        String token = createToken(
                secretKey,
                50L,
                List.of(
                        "USER",
                        "ADMIN"
                )
        );

        Claims claims =
                jwtTokenService.extractClaims(token);

        List<?> roles =
                claims.get(
                        "scope",
                        List.class
                );

        assertNotNull(roles);

        assertEquals(
                2,
                roles.size()
        );

        assertTrue(
                roles.contains("USER")
        );

        assertTrue(
                roles.contains("ADMIN")
        );
    }


    @Test
    void extractClaims_shouldReturnIssuer() {

        String token = createToken(
                secretKey,
                10L,
                List.of("USER")
        );

        Claims claims =
                jwtTokenService.extractClaims(token);

        assertEquals(
                "UserAuthService",
                claims.getIssuer()
        );
    }


    /*
     * =========================================================
     * INVALID EXTRACTION
     * =========================================================
     */

    @Test
    void extractClaims_withMalformedToken_shouldThrowException() {

        assertThrows(
                RuntimeException.class,
                () ->
                        jwtTokenService.extractClaims(
                                "invalid-token"
                        )
        );
    }


    /*
     * =========================================================
     * HELPER
     * =========================================================
     */

    private String createToken(
            SecretKey signingKey,
            Long userId,
            List<String> roles
    ) {

        Date issuedAt =
                new Date();

        Date expiration =
                new Date(
                        issuedAt.getTime()
                                + 60_000
                );

        return Jwts.builder()
                .claim(
                        "userId",
                        userId
                )
                .claim(
                        "scope",
                        roles
                )
                .issuer("UserAuthService")
                .issuedAt(issuedAt)
                .expiration(expiration)
                .signWith(signingKey)
                .compact();
    }
}