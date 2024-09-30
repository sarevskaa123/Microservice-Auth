package com.scalefocus.auth_service.dtos;

import lombok.Data;

@Data
public class LoginResponse {
    private String token;
    private long expiresIn;
    private String message;

    public LoginResponse() {
    }

    public LoginResponse(String message) {
        this.message = message;
    }
}