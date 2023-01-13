package me.sonam.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwt;
import me.sonam.security.jwt.JwtBody;
import me.sonam.security.jwt.JwtException;
import me.sonam.security.jwt.PublicKeyJwtCreator;
import me.sonam.security.jwt.repo.JwtKeyRepository;
import me.sonam.security.jwt.repo.entity.JwtKey;
import okhttp3.mockwebserver.RecordedRequest;
import org.json.JSONException;
import org.json.JSONObject;
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

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Calendar;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.fail;
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
    public void create() throws Exception {
        LOG.info("Create jwt");

        final String clientId = "sonam-123-322";
        final String subject = UUID.randomUUID().toString();
        final String audience = "email"; //the resource to access
        final String scopes = "email.write";

        JwtBody jwtBody = new JwtBody(subject, scopes, clientId, audience, JwtBody.RoleEnum.user.toString(), "admin, manager", 10);

        Mono<String> jwtTokenString = jwtCreator.create(jwtBody);

        jwtTokenString.as(StepVerifier::create).assertNext(jwt -> {
            LOG.info("jwt: {}", jwt);
            assertThat(jwt).isNotNull();

            jwtCreator.getKeyId(jwt).subscribe(keyId -> LOG.info("keyId is not null: {}", keyId));


        }).verifyComplete();


        LOG.info("request to create another jwt token");

        jwtBody = new JwtBody(subject, scopes, clientId, audience, JwtBody.RoleEnum.user.toString(), "employee", 10);

        jwtTokenString = jwtCreator.create(jwtBody);
        jwtTokenString.subscribe(s ->
        LOG.info("jwtTokenString: {}", s)
        );

        jwtKeyRepository.findTop1ByRevokedIsFalse().switchIfEmpty(Mono.error(new JwtException("found empty")))
                .subscribe(jwtKey -> LOG.info("jwtkey: {}", jwtKey));

    }

    public JwtBody getFromString(final String payload) {
        ObjectMapper objectMapper = new ObjectMapper();

        JwtBody jwtBody = null;
        try {
            return objectMapper.readValue(payload, JwtBody.class);

        } catch (JsonProcessingException e) {
            LOG.error("failed to marshal payload to jwtBody type", e);
            fail("failed to marshal payload to JwtBody");
            return null;
        }
    }
}
