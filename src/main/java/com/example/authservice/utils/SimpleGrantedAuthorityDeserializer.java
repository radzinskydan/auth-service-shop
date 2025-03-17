package com.example.authservice.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;

public class SimpleGrantedAuthorityDeserializer extends JsonDeserializer<SimpleGrantedAuthority> {
    @Override
    public SimpleGrantedAuthority deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode node = p.getCodec().readTree(p);
        String authority = node.get("authority").asText();
        return new SimpleGrantedAuthority(authority);
    }
}
