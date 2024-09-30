package com.scalefocus.auth_service.service;

import com.scalefocus.auth_service.dtos.LoginUserDto;
import com.scalefocus.auth_service.dtos.RegisterUserDto;
import com.scalefocus.auth_service.dtos.UserDetailsDto;
import com.scalefocus.auth_service.exceptions.UsernameAlreadyExistsException;
import com.scalefocus.auth_service.model.User;
import com.scalefocus.auth_service.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User signup(RegisterUserDto input) {
        logger.info("Attempting to register user: {}", input.getUsername());
        if(userRepository.findByUsername(input.getUsername()).isPresent()) {
            logger.warn("Username '{}' is already taken", input.getUsername());
            throw new UsernameAlreadyExistsException("Username '" + input.getUsername() +"' is already taken");
        }

        User user = new User(
                input.getUsername(),
                passwordEncoder.encode(input.getPassword()));

        List<String> authorities = input.getRoles() != null ?
                input.getRoles() : List.of("ROLE_USER");  // ROLE_ADMIN

        user.setRoles(authorities);
        logger.info("User '{}' registered successfully", user.getUsername());
        return userRepository.save(user);
    }

    public User authenticate(LoginUserDto input) {
        logger.info("Attempting to authenticate user: {}", input.getUsername());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getUsername(),
                        input.getPassword()
                )
        );

        return userRepository.findByUsername(input.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public User findByUsername(String username) {
        if(userRepository.findByUsername(username).isPresent()) {
            return userRepository.findByUsername(username).get();
        }
        return null;
    }

    public List<UserDetailsDto> getAllUsers() {
        return userRepository.findAll().stream()
                .map(user -> new UserDetailsDto(user.getUsername(), user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())))
                .collect(Collectors.toList());
    }

    public void deleteUser(String username) {
        logger.info("Attempting to delete user: {}", username);
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        userRepository.delete(user);
        logger.info("User with username: {} deleted successfully", username);
    }

}
