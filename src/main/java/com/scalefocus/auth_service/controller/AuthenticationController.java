package com.scalefocus.auth_service.controller;

import com.scalefocus.auth_service.dtos.LoginResponse;
import com.scalefocus.auth_service.dtos.LoginUserDto;
import com.scalefocus.auth_service.dtos.RegisterUserDto;
import com.scalefocus.auth_service.dtos.UserDetailsDto;
import com.scalefocus.auth_service.model.User;
import com.scalefocus.auth_service.service.AuthenticationService;
import com.scalefocus.auth_service.service.JwtService;
import io.jsonwebtoken.JwtException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

@RequestMapping("/auth")
@RestController
@RequiredArgsConstructor
public class AuthenticationController {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);
    private final JwtService jwtService;

    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    @Operation(summary = "Register a new user", description = "Register a new user with a username and password.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User registered successfully"),
            @ApiResponse(responseCode = "400", description = "Username is already taken", content = @Content(schema = @Schema(implementation = String.class)))
    })
    public ResponseEntity<User> register(@RequestBody RegisterUserDto registerUserDto) {
        logger.info("Registering new user: {}", registerUserDto.getUsername());
        User registeredUser = authenticationService.signup(registerUserDto);

        logger.info("User registered successfully: {}", registeredUser.getUsername());
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    @Operation(summary = "Authenticate user", description = "Authenticate a user and return a JWT token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully authenticated",
                    content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "401", description = "Invalid username or password")
    })
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginUserDto loginUserDto) {
        logger.info("Authenticating user: {}", loginUserDto.getUsername());
        try {
            User authenticatedUser = authenticationService.authenticate(loginUserDto);

            String jwtToken = jwtService.generateToken(authenticatedUser);

            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setToken(jwtToken);
            loginResponse.setExpiresIn(jwtService.getExpirationTime());

            logger.info("User authenticated successfully: {}", authenticatedUser.getUsername());
            return ResponseEntity.ok(loginResponse);
        } catch (BadCredentialsException e) {
            logger.warn("Authentication failed for user: {}", loginUserDto.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new LoginResponse("Invalid username or password"));
        }
    }

    @GetMapping("/validate")
    @Operation(summary = "Validate JWT Token", description = "Validate the provided JWT token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token is valid"),
            @ApiResponse(responseCode = "401", description = "Token is not valid", content = @Content(schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "400", description = "Invalid token format", content = @Content(schema = @Schema(implementation = String.class)))
    })
    public ResponseEntity<String> validateToken(@RequestHeader("Authorization") String authHeader) {
        logger.info("Validating token");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.warn("Invalid Authorization header format");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid token format");
        }

        String token = authHeader.substring(7);

        try {
            boolean isValid = jwtService.validateToken(token);
            logger.info("Token is valid");
            return ResponseEntity.ok("Token is valid");
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("Token is not valid");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is not valid");
        }
    }

    @GetMapping("/user-details")
    @Operation(summary = "Get User Details", description = "Get details of the authenticated user.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User details retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid or expired token")
    })
    public ResponseEntity<UserDetailsDto> getUserDetails(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7);
        if (jwtService.validateToken(token)) {
            String username = jwtService.extractUsername(token);
            User user = authenticationService.findByUsername(username);
            UserDetailsDto userDetailsDto = new UserDetailsDto(user.getUsername(), user.getRoles());
            return ResponseEntity.ok(userDetailsDto);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/users")
    @Operation(summary = "Get all users", description = "Retrieve a list of all users.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User list retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    public ResponseEntity<List<UserDetailsDto>> getAllUsers(@RequestHeader("Authorization") String authHeader) {
        List<UserDetailsDto> users = authenticationService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @DeleteMapping("/users")
    public ResponseEntity<Void> deleteUser(@RequestHeader("Authorization") String authHeader, @RequestParam String username) {
        logger.info("Deleting user with username: {}", username);
        authenticationService.deleteUser(username);

        logger.info("User with username: {} deleted successfully", username);
        return ResponseEntity.noContent().build();
    }

}