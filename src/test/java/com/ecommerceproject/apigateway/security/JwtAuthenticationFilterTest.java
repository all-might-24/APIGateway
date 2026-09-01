package com.ecommerceproject.apigateway.security;

import com.ecommerceproject.apigateway.service.ISessionValidationService;
import com.ecommerceproject.apigateway.service.ITokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private ITokenService tokenService;

    @Mock
    private ISessionValidationService sessionValidationService;

    @Mock
    private WebFilterChain filterChain;

    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    void setUp() {

        jwtAuthenticationFilter =
                new JwtAuthenticationFilter(
                        tokenService,
                        sessionValidationService
                );
    }


    /*
     * =========================================================
     * PUBLIC ENDPOINTS
     * =========================================================
     */

    @Test
    void filter_signupEndpoint_shouldContinueWithoutAuthentication() {

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.POST,
                        "/auth/signup"
                );

        when(filterChain.filter(exchange))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        verify(filterChain)
                .filter(exchange);

        verifyNoInteractions(
                tokenService,
                sessionValidationService
        );
    }


    @Test
    void filter_loginEndpoint_shouldContinueWithoutAuthentication() {

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.POST,
                        "/auth/login"
                );

        when(filterChain.filter(exchange))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        verify(filterChain)
                .filter(exchange);

        verifyNoInteractions(
                tokenService,
                sessionValidationService
        );
    }


    @Test
    void filter_validateTokenEndpoint_shouldContinueWithoutAuthentication() {

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.POST,
                        "/auth/validate-token"
                );

        when(filterChain.filter(exchange))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        verifyNoInteractions(
                tokenService,
                sessionValidationService
        );
    }


    @Test
    void filter_getProducts_shouldContinueWithoutAuthentication() {

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.GET,
                        "/products/10"
                );

        when(filterChain.filter(exchange))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        verify(filterChain)
                .filter(exchange);

        verifyNoInteractions(
                tokenService,
                sessionValidationService
        );
    }


    @Test
    void filter_postProducts_shouldNotBeTreatedAsPublic() {

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.POST,
                        "/products"
                );

        when(filterChain.filter(exchange))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        /*
         * No Authorization header exists, so the filter allows the
         * request to continue unauthenticated. Spring Security will
         * ultimately reject the protected request.
         */
        verify(filterChain)
                .filter(exchange);

        verifyNoInteractions(
                tokenService,
                sessionValidationService
        );
    }


    /*
     * =========================================================
     * AUTHORIZATION HEADER
     * =========================================================
     */

    @Test
    void filter_withoutAuthorizationHeader_shouldContinueUnauthenticated() {

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.GET,
                        "/users/me"
                );

        when(filterChain.filter(exchange))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        verify(filterChain)
                .filter(exchange);

        verifyNoInteractions(
                tokenService,
                sessionValidationService
        );
    }


    @Test
    void filter_withNonBearerHeader_shouldContinueUnauthenticated() {

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.GET,
                        "/users/me",
                        "Basic abc123"
                );

        when(filterChain.filter(exchange))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        verify(filterChain)
                .filter(exchange);

        verifyNoInteractions(
                tokenService,
                sessionValidationService
        );
    }


    /*
     * =========================================================
     * INVALID JWT
     * =========================================================
     */

    @Test
    void filter_withInvalidToken_shouldContinueUnauthenticated() {

        String token = "invalid-token";

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.GET,
                        "/users/me",
                        "Bearer " + token
                );

        when(tokenService.validateToken(token))
                .thenReturn(false);

        when(filterChain.filter(exchange))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        verify(tokenService)
                .validateToken(token);

        verifyNoInteractions(sessionValidationService);

        verify(filterChain)
                .filter(exchange);

        verify(tokenService, never())
                .extractClaims(anyString());
    }


    /*
     * =========================================================
     * INVALID SESSION
     * =========================================================
     */

    @Test
    void filter_withValidTokenButInvalidSession_shouldReturn401() {

        String token = "valid-token";

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.GET,
                        "/users/me",
                        "Bearer " + token
                );

        when(tokenService.validateToken(token))
                .thenReturn(true);

        when(sessionValidationService.isSessionValid(token))
                .thenReturn(Mono.just(false));

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        assertEquals(
                HttpStatus.UNAUTHORIZED,
                exchange.getResponse().getStatusCode()
        );

        verify(tokenService)
                .validateToken(token);

        verify(sessionValidationService)
                .isSessionValid(token);

        verify(filterChain, never())
                .filter(exchange);

        verify(tokenService, never())
                .extractClaims(anyString());
    }


    /*
     * =========================================================
     * VALID USER
     * =========================================================
     */

    @Test
    void filter_withValidTokenAndSession_shouldAuthenticateUser() {

        String token = "valid-token";

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.GET,
                        "/users/me",
                        "Bearer " + token
                );

        Claims claims = Jwts.claims()
                .add("userId", 25L)
                .add(
                        "scope",
                        List.of("USER")
                )
                .build();

        when(tokenService.validateToken(token))
                .thenReturn(true);

        when(sessionValidationService.isSessionValid(token))
                .thenReturn(Mono.just(true));

        when(tokenService.extractClaims(token))
                .thenReturn(claims);

        AtomicReference<Authentication> capturedAuthentication =
                new AtomicReference<>();

        when(filterChain.filter(exchange))
                .thenAnswer(invocation ->
                        ReactiveSecurityContextHolder
                                .getContext()
                                .doOnNext(context ->
                                        capturedAuthentication.set(
                                                context.getAuthentication()
                                        )
                                )
                                .then()
                );

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        Authentication authentication =
                capturedAuthentication.get();

        assertNotNull(authentication);

        assertEquals(
                25L,
                authentication.getPrincipal()
        );

        assertTrue(
                authentication
                        .getAuthorities()
                        .stream()
                        .anyMatch(authority ->
                                authority
                                        .getAuthority()
                                        .equals("ROLE_USER")
                        )
        );

        verify(filterChain)
                .filter(exchange);
    }


    /*
     * =========================================================
     * MULTIPLE ROLES
     * =========================================================
     */

    @Test
    void filter_withMultipleRoles_shouldCreateCorrectAuthorities() {

        String token = "admin-token";

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.POST,
                        "/products",
                        "Bearer " + token
                );

        Claims claims = Jwts.claims()
                .add("userId", 50L)
                .add(
                        "scope",
                        List.of(
                                "USER",
                                "ADMIN"
                        )
                )
                .build();

        when(tokenService.validateToken(token))
                .thenReturn(true);

        when(sessionValidationService.isSessionValid(token))
                .thenReturn(Mono.just(true));

        when(tokenService.extractClaims(token))
                .thenReturn(claims);

        AtomicReference<Authentication> capturedAuthentication =
                new AtomicReference<>();

        when(filterChain.filter(exchange))
                .thenAnswer(invocation ->
                        ReactiveSecurityContextHolder
                                .getContext()
                                .doOnNext(context ->
                                        capturedAuthentication.set(
                                                context.getAuthentication()
                                        )
                                )
                                .then()
                );

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        Authentication authentication =
                capturedAuthentication.get();

        assertNotNull(authentication);

        assertEquals(
                50L,
                authentication.getPrincipal()
        );

        assertEquals(
                2,
                authentication
                        .getAuthorities()
                        .size()
        );

        assertTrue(
                authentication
                        .getAuthorities()
                        .stream()
                        .anyMatch(authority ->
                                authority
                                        .getAuthority()
                                        .equals("ROLE_USER")
                        )
        );

        assertTrue(
                authentication
                        .getAuthorities()
                        .stream()
                        .anyMatch(authority ->
                                authority
                                        .getAuthority()
                                        .equals("ROLE_ADMIN")
                        )
        );
    }


    /*
     * =========================================================
     * BEARER EXTRACTION
     * =========================================================
     */

    @Test
    void filter_shouldRemoveBearerPrefixBeforeValidation() {

        String token = "actual-jwt-token";

        MockServerWebExchange exchange =
                exchange(
                        HttpMethod.GET,
                        "/users/me",
                        "Bearer " + token
                );

        when(tokenService.validateToken(token))
                .thenReturn(false);

        when(filterChain.filter(exchange))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        jwtAuthenticationFilter.filter(
                                exchange,
                                filterChain
                        )
                )
                .verifyComplete();

        verify(tokenService)
                .validateToken("actual-jwt-token");

        verify(tokenService, never())
                .validateToken("Bearer actual-jwt-token");
    }


    /*
     * =========================================================
     * HELPERS
     * =========================================================
     */

    private MockServerWebExchange exchange(
            HttpMethod method,
            String path
    ) {

        MockServerHttpRequest request =
                MockServerHttpRequest
                        .method(method, path)
                        .build();

        return MockServerWebExchange.from(request);
    }


    private MockServerWebExchange exchange(
            HttpMethod method,
            String path,
            String authorization
    ) {

        MockServerHttpRequest request =
                MockServerHttpRequest
                        .method(method, path)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                authorization
                        )
                        .build();

        return MockServerWebExchange.from(request);
    }
}