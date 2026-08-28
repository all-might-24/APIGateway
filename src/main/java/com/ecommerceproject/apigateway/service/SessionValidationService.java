package com.ecommerceproject.apigateway.service;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class SessionValidationService implements ISessionValidationService{

    private final WebClient.Builder webClientBuilder;

    public SessionValidationService(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    public Mono<Boolean> isSessionValid(String token) {

        return webClientBuilder
                .build()
                .get()
                .uri("http://UserAuthService/session/validate")
                .header(
                        HttpHeaders.AUTHORIZATION,
                        "Bearer " + token
                )
                .retrieve()
                .toBodilessEntity()
                .map(response -> true)
                .onErrorReturn(false);
    }
}
