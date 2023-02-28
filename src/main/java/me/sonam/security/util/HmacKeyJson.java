package me.sonam.security.util;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties
public class HmacKeyJson {
    private List<HmacKeys> hmacKeys = new ArrayList();

    public List<HmacKeys> getHmacKeys() {
        return hmacKeys;
    }

    public void setHmacKeys(List<HmacKeys> hmacKeys) {
        this.hmacKeys = hmacKeys;
    }

    @Override
    public String toString() {
        return "HmacKeyjson{" +
                "jsonHmacKeys=" + hmacKeys +
                '}';
    }


    public static class HmacKeys {
        private String app;

        public HmacKeys(String app){
            this.app = app;
        }

        public HmacKeys() {

        }

        public String getApp() {
            return this.app;
        }

        public void setApp(String app) {
            this.app = app;
        }
    }
}
