package ee.iglu.skeleton.libs.session.impl;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Base64;

@Configuration
class SessionConfig {

    @Bean
    HashFunction tokenSigner(@Value("${lib.session.hmac-key}") String key) {
        return Hashing.hmacSha256(Base64.getDecoder().decode(key));
    }

}
