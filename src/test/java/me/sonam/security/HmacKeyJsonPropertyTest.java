package me.sonam.security;

import me.sonam.security.jwt.repo.entity.HmacKey;
import me.sonam.security.util.HmacKeyJson;
import me.sonam.security.util.Util;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@SpringBootTest
public class HmacKeyJsonPropertyTest {
    private static final Logger LOG = LoggerFactory.getLogger(HmacKeyJsonPropertyTest.class);

    @Autowired
    private HmacKeyJson hmacKeyJson;
    @Test
    public void hmackeysAppLoading() {
        LOG.info("hmackeys loading testing");

        assertThat(hmacKeyJson.getHmacKeys().size()).isEqualTo(2);

        HmacKey hmacKey = Util.getHmacKeyFromJson(hmacKeyJson.getHmacKeys().get(0).getApp());
        assertThat(hmacKey.getAlgorithm()).isEqualTo("HmacMD5");
        assertThat(hmacKey.getSecretKey()).isEqualTo("mysecret");
        assertThat(hmacKey.getClientId()).isEqualTo("authentication-rest-service");

        hmacKey = Util.getHmacKeyFromJson(hmacKeyJson.getHmacKeys().get(1).getApp());
        assertThat(hmacKey.getAlgorithm()).isEqualTo("HmacMD5");
        assertThat(hmacKey.getSecretKey()).isEqualTo("mysecret");
        assertThat(hmacKey.getClientId()).isEqualTo("email-rest-service");

    }
}
