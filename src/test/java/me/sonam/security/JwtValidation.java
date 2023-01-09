package me.sonam.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwt;
import me.sonam.security.jwt.JwtBody;
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

        JwtKey jwtKey = jwtCreator.createJwtKey();
        jwtKeyRepository.save(jwtKey).subscribe(jwtKey1 -> LOG.info("saved jwtKey: {}", jwtKey1));

        final String clientId = "sonam-123-322";
        final String subject = UUID.randomUUID().toString();
        final String audience = "email"; //the resource to access
        final String scopes = "email.write";
        Duration tenSecondsDuration = Duration.ofSeconds(10);

        JwtBody jwtBody = new JwtBody(subject, scopes, clientId, audience, tenSecondsDuration.toString());

        Mono<String> jwtTokenString = jwtCreator.create(jwtBody);

        jwtTokenString.as(StepVerifier::create).assertNext(jwt -> {
            LOG.info("jwt: {}", jwt);
            String[] parts = jwt.split("\\.");
            try {
                JSONObject header = new JSONObject(new String(Base64.getUrlDecoder().decode(parts[0])));
                JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(parts[1])));
                String signature = new String(Base64.getUrlDecoder().decode(parts[2]));
                LOG.info("header: {},\n payload: {},\n signature: {}", header, payload, signature);

                LOG.info("jwtBody: {}", getFromString(payload.toString()));
            }
            catch (JSONException jse) {
                LOG.error("Failed to parse to json", jse);
            }

            assertThat(jwt).isNotNull();
            assertThat(jwtCreator.getPublicKey(jwtKey.getId())).isNotNull();
            jwtCreator.getPublicKey(jwtKey.getId()).subscribe(key -> LOG.info("public key is {}", key));
        }).verifyComplete();
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
