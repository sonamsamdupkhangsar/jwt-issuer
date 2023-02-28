package me.sonam.security.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import me.sonam.security.jwt.repo.JwtKeyRepository;
import me.sonam.security.jwt.repo.entity.HmacKey;
import me.sonam.security.jwt.repo.HmacKeyRepository;
import me.sonam.security.jwt.repo.entity.JwtKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
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
    public enum Md5Algorithm {
        HmacSHA256
    }
    @Value("${jwt.issuer}")
    private String issuer;

    @Autowired
    private JwtKeyRepository jwtKeyRepository;

    @Autowired
    private HmacKeyRepository hmacKeyRepository;

    public PublicKeyJwtCreator() {
    }

    private Mono<JwtKey> generateKey() {
        LOG.debug("generate key");
        try {
            JwtKey jwtKey = createJwtKey();
            return jwtKeyRepository.save(jwtKey);
        } catch (Exception e) {
            LOG.error("failed to generate rsa public/private keys", e);
            return Mono.error(new JwtException("failed to generate key"));
        }
    }

    @Override
    public Mono<String> create(JwtBody jwtBody) {
        LOG.info("create jwt token from body");

        return jwtKeyRepository.existsTop1ByRevokedIsFalse().
                flatMap(aBoolean -> {
                    if (aBoolean == false) {
                        LOG.debug("no existing jwtKey found");
                        return generateKey();
                    }
                    else {
                        LOG.debug("returning an existing jwtKey");
                        return jwtKeyRepository.findTop1ByRevokedIsFalse();
                    }
                })
                .flatMap(jwtKey -> {
            LOG.info("hello");
            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            Date issueDate = calendar.getTime();

            Duration duration = Duration.ofSeconds(jwtBody.getExpiresInSeconds());

            calendar.add(Calendar.SECOND, (int)duration.getSeconds());

            Date expireDate = calendar.getTime();

            LOG.debug("load private key");
            Key privateKey = loadPrivateKey(jwtKey.getPrivateKey());

            LOG.debug("add claims to jwt");
            Map<String, Object> claimsMap = new HashMap<>();
            claimsMap.put("clientId", jwtBody.getClientId());
            claimsMap.put("scope", jwtBody.getScope());
            claimsMap.put("keyId", jwtKey.getId() != null ? jwtKey.getId().toString() : null);
            claimsMap.put("role", jwtBody.getRole());
            claimsMap.put("groups", jwtBody.getGroups());

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
        LOG.debug("generate RSAKeys");
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
        LOG.debug("createJwtKey");

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

    @Override
    public Mono<String> getKeyId(String jwt) {
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            Base64.Decoder decoder = Base64.getUrlDecoder();

            String[] chunks = jwt.split("\\.");
            if (chunks.length >= 2) {
                final String payload = new String(decoder.decode(chunks[1]));

                JwtBody jwtBody = objectMapper.readValue(payload, JwtBody.class);
                LOG.debug("jwtBody: {}", jwtBody);
                LOG.info("returning keyId: {}", jwtBody.getKeyId());
                return Mono.just(jwtBody.getKeyId().toString());
            }
            else {
                LOG.error("jwt chunk length: {}, jwt: {}", chunks.length, jwt);
                return Mono.error(new JwtException("jwt is invalid, jwt split is less than 2"));
            }
        } catch (JsonProcessingException e) {
            LOG.error("failed to marshal to jwtBody", e);
            return Mono.error(new JwtException("Failed to convert the jwt token to get keyId, error: "+ e.getMessage()));
        }

    }

    public static String getJson(Object object) {
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            final String jsonBody = objectMapper.writeValueAsString(object);
            LOG.debug("jsonBody: {}", jsonBody);

            return jsonBody;
        } catch (JsonProcessingException e) {
            LOG.error("failed to marshal to json", e);
            throw new JwtException("Failed to convert the jwt json, error: "+ e.getMessage());
        }
    }

    @Override
    public Mono<HmacKey> generateKey(String clientId, String key) {
        LOG.info("generate HmacKey for clientId: {}", clientId);

        HmacKey hmacKey = new HmacKey(true, clientId, key, Md5Algorithm.HmacSHA256.name(), true);
        hmacKeyRepository.save(hmacKey).subscribe(hmacKey1 -> LOG.info("saved hmacKey {}", hmacKey1));
        return hmacKeyRepository.findById(clientId);
    }

    public static String getHmac(String algorithm, String data, String key) {
        LOG.info("generating hmac");

        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKeySpec);
            return HexFormat.of().formatHex(mac.doFinal(data.getBytes()));
        }
        catch (Exception e) {
            LOG.error("Exception occured in generating hmac", e);
            return null;
        }
    }

    @Override
    public Mono<Boolean> hmacMatches(final String dataHmacSHA256Value, final String data, final String clientId) {
        return hmacKeyRepository.findById(clientId)
                .switchIfEmpty(Mono.error(new JwtException("No hmacKey found with clientId")))
                .flatMap(hmacKey -> {
                    LOG.info("user hmac: {}, data: {}, clientId: {}", dataHmacSHA256Value, data, clientId);

                    LOG.info("checking hmac signature");
                    final String hmac = getHmac(hmacKey.getHmacMD5Algorithm(), data, hmacKey.getSecretKey());
                    LOG.debug("hmac computed value: '{}', vs client supplied hmacSHA256Value: '{}'", hmac, dataHmacSHA256Value);

                    if (hmac.equals(dataHmacSHA256Value)) {
                        LOG.debug("hmac value matches");
                        return Mono.just(true);
                    } else {
                        LOG.error("hmac does not match");
                        return Mono.just(false);
                    }
                });
    }

}
