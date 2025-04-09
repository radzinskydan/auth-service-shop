package com.example.authservice.controller;

import com.example.authservice.entity.User;
import com.example.authservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/users")
public class UserController {

    private final AuthService authService;

    public UserController(AuthService authService) {
        this.authService = authService;
    }

    @Operation(summary = "Получить список всех пользователей")
    @GetMapping("/getAll")
    public ResponseEntity<?> getUsers() {
        try {
//            authService.validateAdminToken(tokenHeader);
            List<User> allUsers = authService.getAllUsers();
            return ResponseEntity.ok(allUsers);
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (RuntimeException e) {
            if (e.getMessage().contains("Неверный формат токена") || e.getMessage().contains("Неверный JWT токен")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", e.getMessage()));
            } else if (e.getMessage().contains("Доступ запрещен")) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", e.getMessage()));
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Внутренняя ошибка сервера"));
            }
        }
    }



}
