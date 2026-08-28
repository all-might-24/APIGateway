package com.ecommerceproject.apigateway.service;

import io.jsonwebtoken.Claims;

public interface ITokenService {

    boolean validateToken(String token);

    Claims extractClaims(String token);
}
