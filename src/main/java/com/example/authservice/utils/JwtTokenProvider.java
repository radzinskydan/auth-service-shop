package com.example.authservice.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpiration;
    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final RedisTemplate<String, String> redisTemplate;

    public JwtTokenProvider(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }


    public String generateToken(Authentication authentication) {
        log.info("Generating token for authentication: {}", authentication);

        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        log.info("User principal: {}", userPrincipal);

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration * 1000L); // Преобразование в миллисекунды

        log.info("Token details: Issued at {}, Expiration date {}", now, expiryDate);


        List<String> roles = userPrincipal.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());


        Claims claims = Jwts.claims().setSubject(userPrincipal.getUsername());
        claims.put("roles", String.join(",", roles));

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret.getBytes())
                .compact();

        log.info("Generated token: {}", token);

        redisTemplate.opsForValue().set(token, userPrincipal.getUsername(), jwtExpiration, TimeUnit.SECONDS);

        return token;
    }

    public String getUsernameFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.getSubject();
        } catch (Exception e) {
            throw new RuntimeException("Неверный JWT токен");
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SignatureException ex) {
            throw new RuntimeException("Неверная подпись JWT");
        } catch (MalformedJwtException ex) {
            throw new RuntimeException("Неверный JWT токен");
        } catch (ExpiredJwtException ex) {
            throw new RuntimeException("JWT токен истек");
        } catch (UnsupportedJwtException ex) {
            throw new RuntimeException("JWT токен не поддерживается");
        } catch (IllegalArgumentException ex) {
            throw new RuntimeException("JWT claims строка пуста");
        }
    }


}

