package com.example.authservice.service;

import com.example.authservice.entity.User;
import com.example.authservice.exceptions.EmailAlreadyExistsException;
import com.example.authservice.exceptions.UserAlreadyExistsException;
import com.example.authservice.payload.AuthResponse;
import com.example.authservice.repository.AuthRepository;
import com.example.authservice.utils.JwtTokenProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
public class AuthService {

    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;

    public AuthService(AuthRepository authRepository, PasswordEncoder passwordEncoder,
                       JwtTokenProvider tokenProvider, AuthenticationManager authenticationManager) {
        this.authRepository = authRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
    }


    public Optional<User> createUser(User user) {
        if (authRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new UserAlreadyExistsException("Пользователь с таким именем уже существует.");
        }

        if (authRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new EmailAlreadyExistsException("Пользователь с такой электронной почтой уже существует.");
        }

        return Optional.of(createUserWithRole(user, "ROLE_USER"));
    }

    public Optional<User> createAdmin(User user) {

        return Optional.of(createUserWithRole(user, "ROLE_ADMIN"));
    }

    public AuthResponse authenticate(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                username,
                password));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken(authentication);

        User user = authRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));

        return AuthResponse.builder().token(jwt).username(user.getUsername()).build();
    }

    private User createUserWithRole(User user, String role) {
        User newUser = new User();
        newUser.setUsername(user.getUsername());
        newUser.setBalance(user.getBalance());
        newUser.setPassword(passwordEncoder.encode(user.getPassword()));
        newUser.setEmail(user.getEmail());
        List<String> roles = Collections.singletonList(role);
        newUser.setRoles(roles);

        return authRepository.save(newUser);
    }

    public Optional<User> getUserById(Long id) {
        return authRepository.findById(id);
    }


    public Optional<User> findByUsername(String username) {
        return authRepository.findByUsername(username);
    }

    public boolean deleteUser(Long id) {
        if (authRepository.existsById(id)) {
            authRepository.deleteById(id);
            return true;
        }
        return false;
    }

    public List<User> getAllUsers() {
        return authRepository.findAll();
    }

    public void validateAdminToken(String tokenHeader) {
        if (tokenHeader == null || !tokenHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Неверный формат токена");
        }

        String token = tokenHeader.substring(7);
        String username = tokenProvider.getUsernameFromToken(token);
        User admin = findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));

        if (!admin.getRoles().contains("ROLE_ADMIN")) {
            throw new RuntimeException("Доступ запрещен. Требуются права администратора");
        }
    }

}
