package me.sonam.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import me.sonam.security.jwt.JwtBody;
import me.sonam.security.jwt.JwtException;
import me.sonam.security.jwt.PublicKeyJwtCreator;
import me.sonam.security.jwt.repo.JwtKeyRepository;
import me.sonam.security.jwt.repo.entity.HmacKey;
import me.sonam.security.jwt.repo.HmacKeyRepository;
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

    @Autowired
    private HmacKeyRepository hmacKeyRepository;
    final String clientId = "sonam-123-322";
    final String secretKey = "mysecret";
    private HmacKey hmacKey;

    @Test
    public void create() throws Exception {
        LOG.info("Create jwt");

        jwtCreator.generateKey(clientId, secretKey).subscribe(hmacKey1 -> LOG.info("crate a HmacKey: {}", hmacKey1));

        final String subject = UUID.randomUUID().toString();
        final String audience = "email"; //the resource to access
        final String scopes = "email.write";

        JwtBody jwtBody = new JwtBody(subject, scopes, clientId, audience, JwtBody.RoleEnum.user.toString(), "admin, manager", 10);
       // final String hmac = PublicKeyJwtCreator.getHmac(PublicKeyJwtCreator.Md5Algorithm.HmacSHA256.name(), PublicKeyJwtCreator.getJson(jwtBody), secretKey);

        Mono<String> jwtTokenString = jwtCreator.create(jwtBody/*, hmac*/);

        jwtTokenString.as(StepVerifier::create).assertNext(jwt -> {
            LOG.info("jwt: {}", jwt);
            assertThat(jwt).isNotEqualTo("jwt: No key found");
            assertThat(jwt).isNotNull();

            jwtCreator.getKeyId(jwt).subscribe(keyId -> LOG.info("keyId is not null: {}", keyId));


        }).verifyComplete();


        LOG.info("request to create another jwt token");

        jwtBody = new JwtBody(subject, scopes, clientId, audience, JwtBody.RoleEnum.user.toString(), "employee", 10);

        jwtTokenString = jwtCreator.create(jwtBody/*, PublicKeyJwtCreator.getJson(jwtBody)*/);
        jwtTokenString.subscribe(s ->
        LOG.info("jwtTokenString: {}", s)
        );

        jwtKeyRepository.findTop1ByRevokedIsFalse().switchIfEmpty(Mono.error(new JwtException("found empty")))
                .subscribe(jwtKey -> LOG.info("jwtkey: {}", jwtKey));

    }

    @Test
    public void testHmac() {
        final String json = "{\n" +
                "  \"sub\": \"01947sxd184\",\n" +
                "  \"scope\": \"authentication\",\n" +
                "  \"clientId\": \"azudp31223\",\n" +
                "  \"aud\": \"backend\",\n" +
                "  \"role\": \"user\",\n" +
                "  \"groups\": \"email, manager\",\n" +
                "  \"expiresInSeconds\": 300\n" +
                "}\n";

        final String json2 = "{\n" +
                "  \"sub\": \"01947sxd184\"," +
                "  \"scope\": \"authentication\",\n" +
                "  \"clientId\": \"azudp31223\",\n" +
                "  \"aud\": \"backend\",\n" +
                "  \"role\": \"user\",\n" +
                "  \"groups\": \"email, manager\",\n" +
                "  \"expiresInSeconds\": 300\n" +
                "}\n";

        LOG.info("generate hmac key");
        jwtCreator.generateKey(clientId, secretKey).subscribe(hmacKey1 -> LOG.info("crate a HmacKey: {}", hmacKey1));
        final String dataHmacValue = PublicKeyJwtCreator.getHmac(PublicKeyJwtCreator.Md5Algorithm.HmacSHA256.name(), json, secretKey);
        LOG.info("generated hmacValue is {}", dataHmacValue);

        LOG.info("check if service matches");
        jwtCreator.hmacMatches(dataHmacValue, json, clientId).subscribe(aBoolean -> LOG.info("Hmac value matches? {}",aBoolean));
        jwtCreator.hmacMatches(dataHmacValue, json, clientId).as(StepVerifier::create).assertNext(aBoolean -> assertThat(aBoolean).isTrue()).verifyComplete();

        jwtCreator.hmacMatches(dataHmacValue, json2, clientId).as(StepVerifier::create).assertNext(aBoolean -> assertThat(aBoolean).isFalse()).verifyComplete();
    }
 //   @Test
    public void invalidHmac() {
       LOG.info("try a bad hmac");
        final String subject = UUID.randomUUID().toString();
        final String audience = "email"; //the resource to access
        final String scopes = "email.write";

        jwtCreator.generateKey(clientId, secretKey).subscribe(hmacKey1 -> LOG.info("crate a HmacKey: {}", hmacKey1));

        JwtBody jwtBody = new JwtBody(subject, scopes, clientId, audience, JwtBody.RoleEnum.user.toString(), "admin, manager", 10);

        Mono<String> jwtTokenString = jwtCreator.create(jwtBody/*, "bad hmac"*/);

        jwtTokenString.as(StepVerifier::create).expectError(JwtException.class).verify();
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

   // @Test
    public void noHmacKey() throws Exception {
        LOG.info("Create jwt with no hmac key");
        hmacKeyRepository.deleteAll().subscribe();

        final String subject = UUID.randomUUID().toString();
        final String audience = "email"; //the resource to access
        final String scopes = "email.write";

        JwtBody jwtBody = new JwtBody(subject, scopes, clientId, audience, JwtBody.RoleEnum.user.toString(), "admin, manager", 10);
        final String hmac = PublicKeyJwtCreator.getHmac(PublicKeyJwtCreator.Md5Algorithm.HmacSHA256.name(), PublicKeyJwtCreator.getJson(jwtBody), secretKey);

        Mono<String> jwtTokenString = jwtCreator.create(jwtBody);//, hmac);

        jwtTokenString.as(StepVerifier::create).expectErrorMatches(throwable -> {
            LOG.error("error: {}", throwable.getMessage());
            return throwable.getMessage().equals("No hmacKey found with clientId");
        }).verify();
    }
}
