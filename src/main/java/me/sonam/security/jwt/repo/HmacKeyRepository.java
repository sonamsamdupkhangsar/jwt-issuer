package me.sonam.security.jwt.repo;

import me.sonam.security.jwt.repo.entity.HmacKey;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface HmacKeyRepository extends ReactiveCrudRepository<HmacKey, String> {
}
