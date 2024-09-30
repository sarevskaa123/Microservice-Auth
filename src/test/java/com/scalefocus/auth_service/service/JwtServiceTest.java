package com.scalefocus.auth_service.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JwtServiceTest {
    @InjectMocks
    private JwtService jwtService;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private UserDetails userDetails;

    private String token;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        jwtService = new JwtService();
        jwtService.secretKey = "3cfa76ef14937c1c0ea519f8fc057a80fcd04a7420f8e8bcd0a7567c272e007b";
        jwtService.jwtExpiration = 3600000;
        jwtService.userDetailsService = userDetailsService;
        when(userDetails.getUsername()).thenReturn("testuser");
    }

    @Test
    void generateToken_ShouldGenerateValidToken() {
        token = jwtService.generateToken(userDetails);

        assertNotNull(token);
        assertTrue(token.startsWith("eyJ"));
    }

    @Test
    void extractUsername_ShouldReturnCorrectUsername() {
        token = jwtService.generateToken(userDetails);

        String username = jwtService.extractUsername(token);
        assertEquals("testuser", username);
    }

    @Test
    void validateToken_ShouldReturnTrueForValidToken() {
        token = jwtService.generateToken(userDetails);
        when(userDetailsService.loadUserByUsername("testuser")).thenReturn(userDetails);

        boolean isValid = jwtService.validateToken(token);

        assertTrue(isValid);
    }

    @Test
    void validateToken_ShouldThrowExceptionForInvalidToken() {
        String invalidToken = token + "invalid";

        assertThrows(JwtException.class, () -> jwtService.validateToken(invalidToken));
    }

    @Test
    void validateToken_ShouldThrowExceptionForExpiredToken() {
        jwtService.jwtExpiration = -1;
        token = jwtService.generateToken(userDetails);

        assertThrows(JwtException.class, () -> jwtService.validateToken(token));
    }

    @Test
    void isTokenValid_ShouldReturnFalseWhenUsernameDoesNotMatch() {
        token = jwtService.generateToken(userDetails);

        when(userDetailsService.loadUserByUsername("wronguser")).thenReturn(userDetails);

        UserDetails wrongUserDetails = mock(UserDetails.class);
        when(wrongUserDetails.getUsername()).thenReturn("wronguser");

        boolean isValid = jwtService.isTokenValid(token, wrongUserDetails);

        assertFalse(isValid);
    }

    @Test
    void extractAllClaims_ShouldReturnAllClaims() {
        token = jwtService.generateToken(userDetails);

        Claims claims = jwtService.extractAllClaims(token);

        assertNotNull(claims);
        assertEquals("testuser", claims.getSubject());
    }

    @Test
    void shouldThrowExceptionForInvalidToken() {
        String invalidToken = "invalidToken";
        assertThrows(Exception.class, () -> jwtService.extractAllClaims(invalidToken));
    }

}
