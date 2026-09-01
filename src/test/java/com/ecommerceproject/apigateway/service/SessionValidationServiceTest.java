package com.ecommerceproject.apigateway.service;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class SessionValidationServiceTest {

    /*
     * =========================================================
     * SUCCESS
     * =========================================================
     */

    @Test
    void isSessionValid_whenUserAuthReturnsSuccess_shouldReturnTrue() {

        ExchangeFunction exchangeFunction =
                request -> Mono.just(
                        ClientResponse
                                .create(HttpStatus.OK)
                                .build()
                );

        SessionValidationService sessionValidationService =
                createService(exchangeFunction);

        StepVerifier.create(
                        sessionValidationService
                                .isSessionValid("valid-token")
                )
                .expectNext(true)
                .verifyComplete();
    }


    /*
     * =========================================================
     * AUTHORIZATION HEADER
     * =========================================================
     */

    @Test
    void isSessionValid_shouldSendBearerToken() {

        AtomicReference<ClientRequest> capturedRequest =
                new AtomicReference<>();

        ExchangeFunction exchangeFunction =
                request -> {

                    capturedRequest.set(request);

                    return Mono.just(
                            ClientResponse
                                    .create(HttpStatus.OK)
                                    .build()
                    );
                };

        SessionValidationService sessionValidationService =
                createService(exchangeFunction);

        StepVerifier.create(
                        sessionValidationService
                                .isSessionValid("test-jwt-token")
                )
                .expectNext(true)
                .verifyComplete();

        ClientRequest request =
                capturedRequest.get();

        assertNotNull(request);

        assertEquals(
                "Bearer test-jwt-token",
                request.headers()
                        .getFirst(HttpHeaders.AUTHORIZATION)
        );
    }


    /*
     * =========================================================
     * URL / HTTP METHOD
     * =========================================================
     */

    @Test
    void isSessionValid_shouldCallUserAuthSessionValidationEndpoint() {

        AtomicReference<ClientRequest> capturedRequest =
                new AtomicReference<>();

        ExchangeFunction exchangeFunction =
                request -> {

                    capturedRequest.set(request);

                    return Mono.just(
                            ClientResponse
                                    .create(HttpStatus.OK)
                                    .build()
                    );
                };

        SessionValidationService sessionValidationService =
                createService(exchangeFunction);

        StepVerifier.create(
                        sessionValidationService
                                .isSessionValid("token")
                )
                .expectNext(true)
                .verifyComplete();

        ClientRequest request =
                capturedRequest.get();

        assertNotNull(request);

        assertEquals(
                "http://UserAuthService/session/validate",
                request.url().toString()
        );

        assertEquals(
                "GET",
                request.method().name()
        );
    }


    /*
     * =========================================================
     * USER AUTH RETURNS 401
     * =========================================================
     */

    @Test
    void isSessionValid_whenUserAuthReturns401_shouldReturnFalse() {

        ExchangeFunction exchangeFunction =
                request -> Mono.just(
                        ClientResponse
                                .create(HttpStatus.UNAUTHORIZED)
                                .build()
                );

        SessionValidationService sessionValidationService =
                createService(exchangeFunction);

        StepVerifier.create(
                        sessionValidationService
                                .isSessionValid("expired-token")
                )
                .expectNext(false)
                .verifyComplete();
    }


    /*
     * =========================================================
     * USER AUTH RETURNS 500
     * =========================================================
     */

    @Test
    void isSessionValid_whenUserAuthReturns500_shouldReturnFalse() {

        ExchangeFunction exchangeFunction =
                request -> Mono.just(
                        ClientResponse
                                .create(
                                        HttpStatus.INTERNAL_SERVER_ERROR
                                )
                                .build()
                );

        SessionValidationService sessionValidationService =
                createService(exchangeFunction);

        StepVerifier.create(
                        sessionValidationService
                                .isSessionValid("token")
                )
                .expectNext(false)
                .verifyComplete();
    }


    /*
     * =========================================================
     * CONNECTION FAILURE
     * =========================================================
     */

    @Test
    void isSessionValid_whenUserAuthIsUnavailable_shouldReturnFalse() {

        ExchangeFunction exchangeFunction =
                request -> Mono.error(
                        new RuntimeException(
                                "UserAuthService unavailable"
                        )
                );

        SessionValidationService sessionValidationService =
                createService(exchangeFunction);

        StepVerifier.create(
                        sessionValidationService
                                .isSessionValid("token")
                )
                .expectNext(false)
                .verifyComplete();
    }


    /*
     * =========================================================
     * EMPTY TOKEN
     * =========================================================
     */

    @Test
    void isSessionValid_withEmptyToken_shouldStillSendBearerHeader() {

        AtomicReference<ClientRequest> capturedRequest =
                new AtomicReference<>();

        ExchangeFunction exchangeFunction =
                request -> {

                    capturedRequest.set(request);

                    return Mono.just(
                            ClientResponse
                                    .create(HttpStatus.UNAUTHORIZED)
                                    .build()
                    );
                };

        SessionValidationService sessionValidationService =
                createService(exchangeFunction);

        StepVerifier.create(
                        sessionValidationService
                                .isSessionValid("")
                )
                .expectNext(false)
                .verifyComplete();

        ClientRequest request =
                capturedRequest.get();

        assertNotNull(request);

        assertEquals(
                "Bearer ",
                request.headers()
                        .getFirst(HttpHeaders.AUTHORIZATION)
        );
    }


    /*
     * =========================================================
     * HELPER
     * =========================================================
     */

    private SessionValidationService createService(
            ExchangeFunction exchangeFunction
    ) {

        WebClient webClient =
                WebClient.builder()
                        .exchangeFunction(exchangeFunction)
                        .build();

        WebClient.Builder webClientBuilder =
                webClient.mutate();

        return new SessionValidationService(
                webClientBuilder
        );
    }
}