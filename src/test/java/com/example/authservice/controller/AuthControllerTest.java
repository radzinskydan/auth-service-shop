package com.example.authservice.controller;

import com.example.authservice.entity.User;
import com.example.authservice.payload.AuthResponse;
import com.example.authservice.payload.LoginRequest;
import com.example.authservice.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    private MockMvc mockMvc;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
    }

    @Test
    void testAuthenticateUser() throws Exception {
        // Given
        LoginRequest loginRequest = new LoginRequest("username", "password");
        when(authService.authenticate(any(), any())).thenReturn(
                new AuthResponse(loginRequest.getUsername(), loginRequest.getPassword()));

        // When & Then
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(loginRequest)))
                .andExpect(status().isOk());
    }

    @Test
    void testRegisterUser() throws Exception {
        // Given
        User user = new User("username", "password");
        when(authService.createUser(any())).thenReturn(Optional.of(user));

        // When & Then
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(user)))
                .andExpect(status().isCreated());
    }

    @Test
    void testRegisterAdmin() throws Exception {
        // Given
        User user = new User("username", "password");
        when(authService.createAdmin(any())).thenReturn(Optional.of(user));

        // When & Then
        mockMvc.perform(post("/auth/registerAdmin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(user)))
                .andExpect(status().isCreated());
    }

    @Test
    void testGetUserById() throws Exception {
        // Given
        Long userId = 1L;
        User user = new User("username", "password");
        when(authService.getUserById(userId)).thenReturn(Optional.of(user));

        // When & Then
        mockMvc.perform(get("/auth/getById")
                        .param("userId", String.valueOf(userId)))
                .andExpect(status().isOk());
    }

    @Test
    void testGetUserByIdNotFound() throws Exception {
        // Given
        Long userId = 1L;
        when(authService.getUserById(userId)).thenReturn(null);

        // When & Then
        mockMvc.perform(get("/auth/getById")
                        .param("userId", String.valueOf(userId)))
                .andExpect(status().isOk()); // Проверьте статус ответа в зависимости от реализации
    }

    private static String asJsonString(final Object obj) {
        try {
            return new ObjectMapper().writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

