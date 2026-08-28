package com.ecommerceproject.apigateway.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class FallbackController {

    @GetMapping("/fallback/products")
    public ResponseEntity<Map<String, Object>> productServiceFallback() {

        HttpStatus status = HttpStatus.SERVICE_UNAVAILABLE;
        String message = "Product service is temporarily unavailable";
        return ResponseEntity
                .status(status)
                .body(Map.of(
                        "status", status.value(),
                        "message", message
                ));
    }
}