package me.sonam.security;

import me.sonam.security.jwt.PublicKeyJwtCreator;
import me.sonam.security.jwt.repo.entity.HmacKey;
import me.sonam.security.jwt.repo.HmacKeyRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@ExtendWith(SpringExtension.class)
@DataR2dbcTest
public class HmacKeyRepositoryTest {
    private static final Logger LOG = LoggerFactory.getLogger(HmacKeyRepositoryTest.class);

    @Autowired
    private HmacKeyRepository hmacKeyRepository;

    @Test
    public void save() {
        final String clientId = "123-clientid";
        HmacKey hmacKey = new HmacKey(true, clientId,"mysecret", "HmacMD5", true);
        LOG.info("json for hmacKey: {}", PublicKeyJwtCreator.getJson(hmacKey));

        hmacKeyRepository.save(hmacKey).subscribe(hmacKey1 -> LOG.info("saved hmacKey: {}", hmacKey1));

        hmacKeyRepository.existsById(clientId).subscribe(aBoolean -> LOG.info("must exists key {}", aBoolean));
        Mono<Boolean> mono = hmacKeyRepository.existsById(clientId);
        mono.as(StepVerifier::create).assertNext(aBoolean -> {
            LOG.info("aBoolean: {}", aBoolean);
            assertThat(aBoolean).isTrue();
        }).verifyComplete();
    }
}
