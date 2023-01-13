package me.sonam.security.jwt;

import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

public interface JwtCreator {
    Mono<String> create(JwtBody jwtBody);
    Mono<String> getPublicKey(UUID keyId);
    Mono<String> getKeyId(String jwt);
}
