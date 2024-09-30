package com.scalefocus.auth_service.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scalefocus.auth_service.dtos.LoginResponse;
import com.scalefocus.auth_service.dtos.LoginUserDto;
import com.scalefocus.auth_service.dtos.RegisterUserDto;
import com.scalefocus.auth_service.model.User;
import com.scalefocus.auth_service.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.ArrayList;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest()
@AutoConfigureMockMvc
@ExtendWith(SpringExtension.class)
@ActiveProfiles("test")
public class AuthenticationControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void signup_ShouldRegisterUserSuccessfully() throws Exception {
        RegisterUserDto registerUserDto = new RegisterUserDto("testuser1", "password123", new ArrayList<>());

        mockMvc.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", is("testuser1")))
                .andExpect(jsonPath("$.password", notNullValue()));
    }

    @Test
    void signup_ShouldReturnBadRequestWhenUsernameExists() throws Exception {
        userRepository.save(new User("testuser1", passwordEncoder.encode("password123")));

        RegisterUserDto registerUserDto = new RegisterUserDto("testuser1", "newpassword", new ArrayList<>());

        mockMvc.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Username 'testuser1' is already taken"));
    }

    @Test
    void login_ShouldAuthenticateUserSuccessfully() throws Exception {
        userRepository.save(new User("testuser1", passwordEncoder.encode("password123")));

        LoginUserDto loginUserDto = new LoginUserDto("testuser1", "password123");

        mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", notNullValue()))
                .andExpect(jsonPath("$.expiresIn", greaterThan(0)));
    }

    @Test
    void login_ShouldReturnUnauthorizedWhenCredentialsAreInvalid() throws Exception {
        userRepository.save(new User("testuser1", passwordEncoder.encode("password123")));

        LoginUserDto loginUserDto = new LoginUserDto("testuser1", "wrongpassword");

        mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginUserDto)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", is("Invalid username or password")));
    }

    @Test
    void validate_ShouldReturnValidWhenTokenIsValid() throws Exception {
        User user = new User("testuser1", passwordEncoder.encode("password123"));
        userRepository.save(user);

        LoginUserDto loginUserDto = new LoginUserDto("testuser1", "password123");
        String response = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginUserDto)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        LoginResponse loginResponse = objectMapper.readValue(response, LoginResponse.class);
        String token = loginResponse.getToken();

        mockMvc.perform(get("/auth/validate")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("Token is valid"));
    }

    @Test
    void validate_ShouldReturnUnauthorizedWhenTokenIsInvalid() throws Exception {
        String invalidToken = "invalid.token.value";

        mockMvc.perform(get("/auth/validate")
                        .header("Authorization", "Bearer " + invalidToken))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Token is not valid"));
    }

}



