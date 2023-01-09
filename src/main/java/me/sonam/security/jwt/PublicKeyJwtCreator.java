package me.sonam.security.jwt;

import io.jsonwebtoken.*;
import me.sonam.security.jwt.repo.JwtKeyRepository;
import me.sonam.security.jwt.repo.entity.JwtKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.*;

/**
 * This class will create a JWT string token.
 * User needs to call the interface method {@code #createJwtKey method} with the params.
 * The user params are set in the JWT header such as 'groups', 'clientId', and 'keyId'.
 */
@Service
public class PublicKeyJwtCreator implements JwtCreator {

    private static final Logger LOG = LoggerFactory.getLogger(PublicKeyJwtCreator.class);

    @Value("${jwt.issuer}")
    private String issuer;

    @Autowired
    private JwtKeyRepository jwtKeyRepository;

    public PublicKeyJwtCreator() {
    }

    public void checkForKey() {
        Mono<JwtKey> keyMono = jwtKeyRepository.findTop1ByRevokedIsFalse();
        keyMono.switchIfEmpty(generateKey()).subscribe();
    }

    private Mono<JwtKey> generateKey() {
        LOG.debug("generate key");
        try {
            JwtKey jwtKey = createJwtKey();
            return jwtKeyRepository.save(jwtKey);
        } catch (Exception e) {
            LOG.error("failed to generate rsa public/private keys", e);
            return Mono.error(new io.jsonwebtoken.JwtException("failed to generate key"));
        }
    }

    @Override
    public Mono<String> create(JwtBody jwtBody) {
        checkForKey();

        return jwtKeyRepository.findTop1ByRevokedIsFalse().flatMap(jwtKey -> {
            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            Date issueDate = calendar.getTime();

            Duration duration = Duration.parse(jwtBody.getJwtExpiresInDuration());

            calendar.add(Calendar.SECOND, (int)duration.getSeconds());

            Date expireDate = calendar.getTime();

            Key privateKey = loadPrivateKey(jwtKey.getPrivateKey());

            Map<String, Object> claimsMap = new HashMap<>();
            claimsMap.put("clientId", jwtBody.getClientId());
            claimsMap.put("scope", jwtBody.getScope());
            claimsMap.put("keyId", jwtKey.getId() != null ? jwtKey.getId().toString() : null);

            String jwt = Jwts.builder()
                    .setSubject(jwtBody.getSub())
                    .setIssuer(issuer)
                    .setAudience(jwtBody.getAud())
                    .setIssuedAt(issueDate)
                    .addClaims(claimsMap)
                    .setExpiration(expireDate)
                    .setId(UUID.randomUUID().toString())
                    .signWith(SignatureAlgorithm.RS512, privateKey)
                    .compact();

            LOG.debug("returning jwt");
            return Mono.just(jwt);
        }).switchIfEmpty(Mono.just("No key found"));
    }

    private static Map<String, Object> generateRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return Map.of("private", keyPair.getPrivate(), "public", keyPair.getPublic());
    }

    public Key loadPrivateKey(String stored) {
        try {
            PKCS8EncodedKeySpec keySpec =
                    new PKCS8EncodedKeySpec(
                            Base64.getDecoder().decode(stored.getBytes(StandardCharsets.UTF_8)));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        } catch (GeneralSecurityException gse) {
            LOG.error("exception occured", gse);
            return null;
        }
    }

    public JwtKey createJwtKey() throws Exception {
        Map<String, Object> rsaKeys = generateRSAKeys();

        final String publicKeyString = Base64.getEncoder().encodeToString(((PublicKey) rsaKeys.get("public")).getEncoded());
        final String privateKeyString = Base64.getEncoder().encodeToString(((PrivateKey) rsaKeys.get("private")).getEncoded());

        return new JwtKey(privateKeyString, publicKeyString);
    }

    @Override
    public Mono<String> getPublicKey(UUID keyId) {
        LOG.info("get public key for keyId: {}", keyId);

        jwtKeyRepository.count().subscribe(aLong -> LOG.info("found {} rows of jwtKeys", aLong));
        jwtKeyRepository.findById(keyId).subscribe(jwtKey -> LOG.info("for id: {} found jwtKey: {}", keyId, jwtKey));

        return  jwtKeyRepository.findById(keyId)
                .map(jwtKey -> jwtKey.getPublicKey())
                .doOnNext(s -> LOG.info("publicKey: {}", s))
                .map(s -> s);
    }
}
