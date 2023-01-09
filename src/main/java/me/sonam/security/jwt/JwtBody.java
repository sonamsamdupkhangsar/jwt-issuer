package me.sonam.security.jwt;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtBody {
    private static final Logger LOG = LoggerFactory.getLogger(JwtBody.class);

    private String keyId;
    private String sub;
    private String scope;
    private String clientId;
    private String aud;
    private String jwtExpiresInDuration;
    private String exp;
    private String iat;
    private String jti;
    private String iss;

    public JwtBody() {

    }

    public JwtBody(String sub, String scope, String clientId, String aud, String jwtExpiresInDuration) {
        this.sub = sub;

        this.scope = scope;
        this.clientId = clientId;
        this.aud = aud;
        this.jwtExpiresInDuration = jwtExpiresInDuration;

        if (this.sub.isEmpty()) {
            throw new JwtException("subject is empty");
        }

        if (this.scope.isEmpty()) {
            throw new JwtException("scopes is emtpy");
        }

        if (this.clientId.isEmpty()) {
            LOG.warn("clientId is empty");
        }
        if (this.aud.isEmpty()) {
            throw new JwtException("audience is empty");
        }
    }

    public String getSub() {
        return sub;
    }

    public String getKeyId() {
        return keyId;
    }



    public String getJwtExpiresInDuration() {
        return jwtExpiresInDuration;
    }

    public void setJwtExpiresInDuration(String jwtExpiresInDuration) {
        this.jwtExpiresInDuration = jwtExpiresInDuration;
    }

    public String getScope() {
        return scope;
    }

    public String getClientId() {
        return clientId;
    }

    public String getAud() {
        return aud;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getIss() {
        return iss;
    }

    public String getExp() {
        return exp;
    }

    public String getJti() {
        return jti;
    }

    public String getIat() {
        return iat;
    }

    @Override
    public String toString() {
        return "JwtBody{" +
                "keyId='" + keyId + '\'' +
                ", sub='" + sub + '\'' +
                ", scope='" + scope + '\'' +
                ", clientId='" + clientId + '\'' +
                ", aud='" + aud + '\'' +
                ", jwtExpiresInDuration='" + jwtExpiresInDuration + '\'' +
                ", exp='" + exp + '\'' +
                ", iat='" + iat + '\'' +
                ", jti='" + jti + '\'' +
                ", iss='" + iss + '\'' +
                '}';
    }
}
