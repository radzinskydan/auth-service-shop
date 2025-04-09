package com.example.authservice.controller;

import com.example.authservice.entity.User;
import com.example.authservice.payload.AuthResponse;
import com.example.authservice.payload.LoginRequest;
import com.example.authservice.repository.AuthRepository;
import com.example.authservice.service.AuthService;
import com.example.authservice.utils.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.function.Function;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.authenticate(loginRequest.getUsername(), loginRequest.getPassword()));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        return handleUserRegistration(user, authService::createUser);
    }

    @PostMapping("/registerAdmin")
    public ResponseEntity<?> registerAdmin(@RequestBody User user) {
        return handleUserRegistration(user, authService::createAdmin);
    }

    private ResponseEntity<?> handleUserRegistration(User user, Function<User, Optional<User>> registrationFunction) {
        return registrationFunction.apply(user).map(newUser -> {
            AuthResponse response = AuthResponse.builder().username(newUser.getUsername()).build();
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        }).orElse(ResponseEntity.badRequest().build());
    }

    @GetMapping("/getById")
    public ResponseEntity<?> getUser(@RequestParam Long userId) {
        return ResponseEntity.ok(authService.getUserById(userId));
    }


//    @GetMapping("/me")
//    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
//        try {
//            String token = request.getHeader("Authorization");
//            if (token != null && token.startsWith("Bearer ")) {
//                token = token.substring(7);
//                String username = tokenProvider.getUsernameFromToken(token);
//
//                User user = authService.getByUsername(username)
//                        .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));
//
//                return ResponseEntity.ok(AuthResponse.builder()
//                        .username(user.getUsername())
//                        .build());
//            }
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
//                    .body(Map.of("error", "Токен не найден"));
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
//                    .body(Map.of("error", e.getMessage()));
//        }
//    }
}
