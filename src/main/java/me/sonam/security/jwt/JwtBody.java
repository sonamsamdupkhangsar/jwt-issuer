package me.sonam.security.jwt;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtBody {
    private static final Logger LOG = LoggerFactory.getLogger(JwtBody.class);

    private String subject;
    private String scopes;
    private String clientId;
    private String audience;

    private String jwtExpiresInDuration;

    public JwtBody() {

    }

    public JwtBody(String subject, String scopes, String clientId, String audience, String jwtExpiresInDuration) {
        this.subject = subject;

        this.scopes = scopes;
        this.clientId = clientId;
        this.audience = audience;
        this.jwtExpiresInDuration = jwtExpiresInDuration;

        if (this.subject.isEmpty()) {
            throw new JwtException("subject is empty");
        }

        if (this.scopes.isEmpty()) {
            throw new JwtException("scopes is emtpy");
        }

        if (this.clientId.isEmpty()) {
            LOG.warn("clientId is empty");
        }
        if (this.audience.isEmpty()) {
            throw new JwtException("audience is empty");
        }
    }

    public String getSubject() {
        return subject;
    }


    public String getJwtExpiresInDuration() {
        return jwtExpiresInDuration;
    }

    public void setJwtExpiresInDuration(String jwtExpiresInDuration) {
        this.jwtExpiresInDuration = jwtExpiresInDuration;
    }

    public String getScopes() {
        return scopes;
    }

    public String getClientId() {
        return clientId;
    }

    public String getAudience() {
        return audience;
    }

}
