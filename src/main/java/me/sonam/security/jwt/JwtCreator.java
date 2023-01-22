package me.sonam.security.jwt;

import me.sonam.security.jwt.repo.entity.HmacKey;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

public interface JwtCreator {
    Mono<String> create(JwtBody jwtBody);
    Mono<String> getPublicKey(UUID keyId);
    Mono<String> getKeyId(String jwt);
    Mono<HmacKey> generateKey(String clientId, String yourKey);
    Mono<Boolean> hmacMatches(final String dataHmacSHA256Value, final String data, final String clientId);
}
