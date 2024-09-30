package com.scalefocus.auth_service.dtos;

import lombok.Data;

import java.util.List;

@Data
public class RegisterUserDto extends UserCredentialsDto{
    private List<String> roles;

    public RegisterUserDto(String username, String password, List<String> roles) {
        super(username, password);
        this.roles = roles;
    }
}
