package com.scalefocus.auth_service.service;

import com.scalefocus.auth_service.dtos.LoginUserDto;
import com.scalefocus.auth_service.dtos.RegisterUserDto;
import com.scalefocus.auth_service.exceptions.UsernameAlreadyExistsException;
import com.scalefocus.auth_service.model.User;
import com.scalefocus.auth_service.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthenticationService authenticationService;

    @Test
    void signup_ShouldRegisterUserSuccessfully() {
        RegisterUserDto registerUserDto = new RegisterUserDto("testuser2", "password123", new ArrayList<>());
        User user = new User("testuser2", "encodedPassword");

        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenReturn(user);

        User result = authenticationService.signup(registerUserDto);

        assertNotNull(result);
        assertEquals("testuser2", result.getUsername());
        assertEquals("encodedPassword", result.getPassword());

        verify(userRepository, times(1)).save(any(User.class));
        verify(passwordEncoder, times(1)).encode("password123");
    }

    @Test
    void signup_ShouldThrowExceptionWhenUsernameExists() {
        RegisterUserDto registerUserDto = new RegisterUserDto("existingUser", "password123", new ArrayList<>());
        when(userRepository.findByUsername("existingUser")).thenReturn(Optional.of(new User()));

        assertThrows(UsernameAlreadyExistsException.class, () -> authenticationService.signup(registerUserDto));

        verify(userRepository, times(1)).findByUsername("existingUser");
        verify(userRepository, times(0)).save(any(User.class));
    }

    @Test
    void authenticate_ShouldAuthenticateUserSuccessfully() {
        LoginUserDto loginUserDto = new LoginUserDto("testuser", "password123");
        User user = new User("testuser", "encodedPassword");

        UserRepository userRepository = mock(UserRepository.class);
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken("testuser", "password123"));

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

        AuthenticationService authenticationService = new AuthenticationService(
                userRepository,
                authenticationManager,
                passwordEncoder
        );

        User result = authenticationService.authenticate(loginUserDto);

        assertNotNull(result);
        assertEquals("testuser", result.getUsername());

        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken("testuser", "password123")
        );
        verify(userRepository, times(1)).findByUsername("testuser");
    }

    @Test
    void authenticate_ShouldThrowExceptionWhenCredentialsAreInvalid() {
        LoginUserDto loginUserDto = new LoginUserDto("testuser", "wrongpassword");

        doThrow(new BadCredentialsException("Bad credentials")).when(authenticationManager).authenticate(
                new UsernamePasswordAuthenticationToken("testuser", "wrongpassword")
        );

        assertThrows(BadCredentialsException.class, () -> authenticationService.authenticate(loginUserDto));

        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken("testuser", "wrongpassword")
        );
        verify(userRepository, times(0)).findByUsername(anyString());
    }

    @Test
    void authenticate_ShouldThrowExceptionWhenUserNotFound() {
        LoginUserDto loginUserDto = new LoginUserDto("nonexistentuser", "password123");

        when(authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken("nonexistentuser", "password123")
        )).thenReturn(null);

        when(userRepository.findByUsername("nonexistentuser")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> authenticationService.authenticate(loginUserDto));

        verify(userRepository, times(1)).findByUsername("nonexistentuser");
    }

}

