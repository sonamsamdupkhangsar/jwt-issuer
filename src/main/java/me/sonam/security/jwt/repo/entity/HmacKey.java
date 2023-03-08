package me.sonam.security.jwt.repo.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;

import java.util.Objects;

public class HmacKey implements Persistable<String> {

    @Id
    private String clientId;
    private String algorithm;
    private String secretKey;

    //expired is primitive type so that it will default to false
    private boolean active;

    @Transient
    private boolean newKey = false;

    public HmacKey(boolean newKey, String clientId, String secretKey, String algorithm, boolean active) {
        this.newKey = newKey;
        this.clientId = clientId;
        this.algorithm = algorithm;
        this.secretKey = secretKey;
        this.active = active;
    }

    public HmacKey() {

    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getSecretKey() {
        return this.secretKey;
    }

    public String getClientId() {
        return this.clientId;
    }

    public boolean isActive() {
        return active;
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
        return Objects.equals(algorithm, hmacKey.algorithm) && Objects.equals(clientId, hmacKey.clientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, clientId);
    }

    @Override
    public String toString() {
        return "HmacKey{**not printing**" +
                '}';
    }
}
