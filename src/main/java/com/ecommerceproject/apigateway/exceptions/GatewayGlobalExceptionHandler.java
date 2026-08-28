package com.ecommerceproject.apigateway.exceptions;


import com.ecommerceproject.apigateway.dtos.ErrorResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.cloud.gateway.support.ServiceUnavailableException;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

import org.springframework.cloud.gateway.support.NotFoundException;

import java.time.LocalDateTime;

@Component
@Order(-2)
public class GatewayGlobalExceptionHandler implements WebExceptionHandler {

    private final ObjectMapper objectMapper;

    public GatewayGlobalExceptionHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {

        System.out.println("Gateway exception: " + ex.getClass().getName());
        System.out.println("Gateway exception message: " + ex.getMessage());

        if (exchange.getResponse().isCommitted()) {
            return Mono.error(ex);
        }

        HttpStatus status = determineStatus(ex);

        ErrorResponseDto errorResponse = new ErrorResponseDto(
                status.value(),
                getMessage(status),
                LocalDateTime.now(),
                exchange.getRequest().getPath().value()
        );

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);

            exchange.getResponse().setStatusCode(status);
            exchange.getResponse()
                    .getHeaders()
                    .setContentType(MediaType.APPLICATION_JSON);

            return exchange.getResponse()
                    .writeWith(
                            Mono.just(
                                    exchange.getResponse()
                                            .bufferFactory()
                                            .wrap(bytes)
                            )
                    );

        } catch (Exception serializationException) {
            return Mono.error(serializationException);
        }
    }

    private HttpStatus determineStatus(Throwable ex) {

        if (ex instanceof NotFoundException) {
            return HttpStatus.SERVICE_UNAVAILABLE;
        }

        if (ex instanceof ServiceUnavailableException) {
            return HttpStatus.SERVICE_UNAVAILABLE;
        }

        if (ex instanceof java.net.ConnectException) {
            return HttpStatus.SERVICE_UNAVAILABLE;
        }

        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    private String getMessage(HttpStatus status) {

        if (status == HttpStatus.SERVICE_UNAVAILABLE) {
            return "Service temporarily unavailable";
        }

        return "An unexpected error occurred";
    }
}