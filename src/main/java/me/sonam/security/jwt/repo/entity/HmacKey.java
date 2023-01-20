package me.sonam.security.jwt.repo.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;

import java.util.Objects;

public class HmacKey implements Persistable<String> {

    @Id
    private String clientId;
    private String hmacMD5Algorithm;
    private String secretKey;

    @Transient
    private boolean newKey = false;

    public HmacKey(boolean newKey, String clientId, String secretKey, String hmacMD5Algorithm) {
        this.newKey = newKey;
        this.clientId = clientId;
        this.hmacMD5Algorithm = hmacMD5Algorithm;
        this.secretKey = secretKey;
    }

    public HmacKey() {

    }

    public String getHmacMD5Algorithm() {
        return hmacMD5Algorithm;
    }

    public String getSecretKey() {
        return this.secretKey;
    }

    public String getClientId() {
        return this.clientId;
    }

    @Override
    public String getId() {
        return clientId;
    }

    @Override
    public boolean isNew() {
        return this.newKey;
    }

    public void setIsNew(boolean newKey) {
        this.newKey = newKey;
    }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HmacKey hmacKey = (HmacKey) o;
        return Objects.equals(hmacMD5Algorithm, hmacKey.hmacMD5Algorithm) && Objects.equals(clientId, hmacKey.clientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hmacMD5Algorithm, clientId);
    }

    @Override
    public String toString() {
        return "HmacKey{" +
                "clientId=" + clientId +
                ", hmacMD5Algorithm='" + hmacMD5Algorithm + '\'' +
                ", secretkey='" + secretKey + '\'' +
                ", isNew=" + newKey +
                '}';
    }
}
