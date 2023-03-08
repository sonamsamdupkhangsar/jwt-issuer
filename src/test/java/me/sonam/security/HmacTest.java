package me.sonam.security;

import org.apache.commons.codec.digest.HmacUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import static org.junit.Assert.assertEquals;


public class HmacTest {

    private static final Logger LOG = LoggerFactory.getLogger(HmacTest.class);

    public static String hmacWithApacheCommons(String algorithm, String data, String key) {
        final String hmac = new HmacUtils(algorithm, key).hmacHex(data);
        return hmac;
    }

    @Test
    public void givenDataAndKeyAndAlgorithm_whenHmacWithApacheCommons_thenSuccess() {

        String hmacMD5Value = "621dc816b3bf670212e0c261dc9bcdb6";
        String algorithm = "HmacMD5";
        String data = "baeldung";
        String key = "123456";

        String result = HmacTest.hmacWithApacheCommons(algorithm, data, key);
        LOG.info("result: {}, hmacMD5Value: {}", result, hmacMD5Value);
        assertEquals(hmacMD5Value, result);
    }

    @Test
    public void givenDataAndKeyAndAlgorithm_whenHmacWithJava_thenSuccess()
            throws NoSuchAlgorithmException, InvalidKeyException {

        String hmacSHA256Value = "5b50d80c7dc7ae8bb1b1433cc0b99ecd2ac8397a555c6f75cb8a619ae35a0c35";
        String hmacSHA256Algorithm = "HmacSHA256";
        String data = "baeldung";
        String key = "123456";

        String result = HmacTest.hmacWithJava(hmacSHA256Algorithm, data, key);
        LOG.info("result is {}, actual: {}", result, hmacSHA256Value);

        assertEquals(hmacSHA256Value, result);
    }

    public static String hmacWithJava(String algorithm, String data, String key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKeySpec);
        return HexFormat.of().formatHex(mac.doFinal(data.getBytes()));
    }

}
