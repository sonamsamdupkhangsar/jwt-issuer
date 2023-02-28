package me.sonam.security.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import me.sonam.security.jwt.repo.entity.HmacKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Util {
    private static final Logger LOG = LoggerFactory.getLogger(Util.class);

    public static HmacKey getHmacKeyFromJson(String jsonString) {
        ObjectMapper objectMapper = new ObjectMapper();
        LOG.info("converting json string to HmacKey: {}", jsonString);
        try {
            return objectMapper.readValue(jsonString, HmacKey.class);
        }
        catch (JsonProcessingException e) {
            LOG.error("failed to map to HmacKey from jsonString", e);
            return null;
        }
    }
}
