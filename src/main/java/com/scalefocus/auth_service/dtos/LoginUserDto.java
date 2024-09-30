package com.scalefocus.auth_service.dtos;

import lombok.Data;

@Data
public class LoginUserDto extends UserCredentialsDto{
    public LoginUserDto(String username, String password) {
        super(username, password);
    }
}
