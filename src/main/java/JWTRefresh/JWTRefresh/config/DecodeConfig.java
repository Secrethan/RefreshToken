package JWTRefresh.JWTRefresh.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class DecodeConfig {
    @Bean
    public BCryptPasswordEncoder encodePwd () {
        //단방향 암호화
        return new BCryptPasswordEncoder();
    }
}
