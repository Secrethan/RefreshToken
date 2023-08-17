package JWTRefresh.JWTRefresh.config;


import JWTRefresh.JWTRefresh.config.jwt.Authentication.JWTAuthenticationFilter;
import JWTRefresh.JWTRefresh.config.jwt.Authorization.JwtVerificationFilter;
import JWTRefresh.JWTRefresh.config.jwt.JwtTokenProvider;
import JWTRefresh.JWTRefresh.repository.UserRepository;
import JWTRefresh.JWTRefresh.service.RedisService;
import JWTRefresh.JWTRefresh.service.UserService;
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

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception{
        return authenticationConfiguration.getAuthenticationManager();
    }
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserService userService;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private AES128Config aes128Config;

    @Autowired
    private RedisService redisService;

    public class CustomSecurityFilter extends AbstractHttpConfigurer<CustomSecurityFilter, HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

            JWTAuthenticationFilter jwtAuthenticationFilter = new JWTAuthenticationFilter(authenticationManager,userService,jwtTokenProvider,aes128Config,redisService);
            JwtVerificationFilter jwtVerificationFilter = new JwtVerificationFilter(jwtTokenProvider,redisService);
            jwtAuthenticationFilter.setFilterProcessesUrl("/auth/login");
            builder.addFilter(jwtAuthenticationFilter)
                    .addFilterAfter(jwtVerificationFilter, JWTAuthenticationFilter.class);


            super.configure(builder);


        }
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf().disable();
        http.cors().configurationSource(configurationSource());
        // JWT Token 으로 인증하기 때문에 세션은 필요 없다.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()

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
             //http.apply(new CustomSecurityFilter());
        return http.build();
    }
    public CorsConfigurationSource configurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*"); // GET, POST, PUT, DELETE (Javascript 요청 허용)
        configuration.addAllowedOriginPattern("*"); // 모든 IP 주소 허용 (프론트 앤드 IP만 허용 react)
        configuration.setAllowCredentials(true); // 클라이언트에서 쿠키 요청 허용
        configuration.addExposedHeader("Authorization"); // default
        configuration.addExposedHeader("Refresh");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
