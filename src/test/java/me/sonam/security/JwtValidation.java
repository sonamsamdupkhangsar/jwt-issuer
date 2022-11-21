package me.sonam.security;

import me.sonam.security.jwt.PublicKeyJwtCreator;
import me.sonam.security.jwt.repo.JwtKeyRepository;
import me.sonam.security.jwt.repo.entity.JwtKey;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Calendar;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {Application.class})
public class JwtValidation {
    private static final Logger LOG = LoggerFactory.getLogger(JwtValidation.class);

    @Autowired
    private PublicKeyJwtCreator jwtCreator;

    @Autowired
    private JwtKeyRepository jwtKeyRepository;

    @Test
    public void createJwt() throws Exception {
        LOG.info("Create jwt");

        JwtKey jwtKey = jwtCreator.createJwtKey();
        jwtKeyRepository.save(jwtKey).subscribe(jwtKey1 -> LOG.info("saved jwtKey: {}", jwtKey1));

        final String clientId = "sonam-123-322";
        final String groups = "Admin, Cameramen, Driver, foodballer";
        Mono<String> jwtTokenString = jwtCreator.create(clientId, groups, "sonam-username", "https://sonam.cloud", Calendar.HOUR, 5);

        jwtTokenString.as(StepVerifier::create).assertNext(jwt -> {
            LOG.info("jwt: {}", jwt);
            assertThat(jwt).isNotNull();}).verifyComplete();
    }
}
