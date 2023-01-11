package me.sonam.security;

import me.sonam.security.jwt.repo.JwtKeyRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@DataR2dbcTest
public class JwtKeyRepositoryTest {
    private static final Logger LOG = LoggerFactory.getLogger(JwtKeyRepositoryTest.class);

    @Autowired
    private JwtKeyRepository jwtKeyRepository;
    @Test
    public void apiTest() {
        jwtKeyRepository.findTop1ByRevokedIsFalse();
    }
}
