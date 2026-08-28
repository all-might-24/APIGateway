package com.ecommerceproject.apigateway.service;

import reactor.core.publisher.Mono;

public interface ISessionValidationService {
    Mono<Boolean> isSessionValid(String token);
}
