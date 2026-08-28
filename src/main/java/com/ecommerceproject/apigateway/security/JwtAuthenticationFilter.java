package com.ecommerceproject.apigateway.security;

import com.ecommerceproject.apigateway.service.ISessionValidationService;
import com.ecommerceproject.apigateway.service.ITokenService;
import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    private final ITokenService tokenService;

    private final ISessionValidationService sessionValidationService;

    public JwtAuthenticationFilter(ITokenService tokenService,
                                    ISessionValidationService sessionValidationService) {
        this.tokenService = tokenService;
        this.sessionValidationService = sessionValidationService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        if (isPublicEndpoint(exchange)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange
                .getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        String bearer = "Bearer ";

        if (authHeader == null || !authHeader.startsWith(bearer)) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(bearer.length());

        if (!tokenService.validateToken(token)) {
            return chain.filter(exchange);
        }

        return sessionValidationService
                .isSessionValid(token)
                .flatMap(isValid -> {

                    if (!isValid) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }

                    // Token + session are valid
                    Claims claims = tokenService.extractClaims(token);

                    Long userId = claims.get("userId", Long.class);

                    List<String> roles = claims.get("scope", List.class);

                    List<GrantedAuthority> authorities = roles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .collect(Collectors.toList());

                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                                    userId,
                                    null,
                                    authorities
                            );

                    return chain.filter(exchange)
                            .contextWrite(
                                    ReactiveSecurityContextHolder
                                            .withAuthentication(authentication)
                            );
                });
    }

    private boolean isPublicEndpoint(ServerWebExchange exchange) {

        String path = exchange.getRequest()
                .getURI()
                .getPath();

        HttpMethod method = exchange.getRequest()
                .getMethod();

        if (path.equals("/auth/signup")
                || path.equals("/auth/login")
                || path.equals("/auth/validate-token")
                || path.equals("/fallback/products")
                || path.equals("/actuator/gateway/routes")) {
            return true;
        }

        return HttpMethod.GET.equals(method) && path.startsWith("/products");
    }
}