package JWTRefresh.JWTRefresh.config;

import JWTRefresh.JWTRefresh.config.jwt.CorsConfig;
import JWTRefresh.JWTRefresh.config.jwt.JWTAuthenticationFilter;
import JWTRefresh.JWTRefresh.config.jwt.JWTAuthorizationFilter;
import JWTRefresh.JWTRefresh.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception{
        return authenticationConfiguration.getAuthenticationManager();
    }
    @Autowired
    private CorsConfig corsConfig;
    @Autowired
    private UserRepository userRepository;

    public class CustomSecurityFilter extends AbstractHttpConfigurer<CustomSecurityFilter, HttpSecurity> {

        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            builder.addFilter(new JWTAuthenticationFilter(authenticationManager));
            builder.addFilter(new JWTAuthorizationFilter(authenticationManager,userRepository ));
            super.configure(builder);
        }
    }





    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsConfig.corsFilter())
                .formLogin().disable()
                .httpBasic().disable()
                .apply(new CustomSecurityFilter())
                .and()
                .authorizeRequests()
                .antMatchers("/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .antMatchers("/users/**")
                .access("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
                .anyRequest().permitAll();

        return http.build();
    }
}
