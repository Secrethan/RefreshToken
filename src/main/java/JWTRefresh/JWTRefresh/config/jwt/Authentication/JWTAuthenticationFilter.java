package JWTRefresh.JWTRefresh.config.jwt.Authentication;


import JWTRefresh.JWTRefresh.auth.PrincipalDetails;
import JWTRefresh.JWTRefresh.config.AES128Config;
import JWTRefresh.JWTRefresh.config.jwt.JwtTokenProvider;
import JWTRefresh.JWTRefresh.domain.TokenDTO;
import JWTRefresh.JWTRefresh.domain.User;
import JWTRefresh.JWTRefresh.domain.UserDTO;
import JWTRefresh.JWTRefresh.service.AuthService;
import JWTRefresh.JWTRefresh.service.RedisService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;


// UsernamePasswordAuthenticationFilter : 사용자 요청 정보를 받아 인증을 처리하는 필터
// 해당 필터를 대신해 JWT 토큰을 사용해서 인증할 필터를 만듦
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JWTAuthenticationFilter : 진입 ");

        ObjectMapper om = new ObjectMapper();
        UserDTO userDTO = null;

        try {
            userDTO = om.readValue(request.getInputStream(), UserDTO.class);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        // 인증을 위한 토큰 생성, 토큰을 토대로 인증 시도
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDTO.getUsername(), userDTO.getPassword());
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        /*
            1. UsernamePasswordAuthenticationToken 을 토대로 Authentication 객체 생성
            2. Authentication 객체를 authenticationManager 에 전달
            3. authenticationManager 는 구현체인 ProviderManager 에 등록된 각종 Provider 목록을 순회
            4. DaoAuthenticationProvider
                                         - UserDetailsService 를 통해 userDetails 객체에 담긴 회원 정보와 DB에 회원 정보를 대조
                                         - PasswordEncoder 를 통해 비밀번호 확인
         */

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("인증을 요구한 회원 이름 : " + principalDetails.getUser().getUsername());

        return authentication;
    }

    //  attemptAuthentication 메서드를 통해 정상적으로 인증이 완료되면 successfulAuthentication 메서드가 실행됨
    //  인증 완료된 요청에 대해 JWT 토큰을 생성하고 response header 에 담아 보냄
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행 : 인증 완료 ");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // Refresh , access Token 생성
        TokenDTO tokenDTO = jwtTokenProvider.generateTokenDTO(principalDetails);
        String accessToken = tokenDTO.getAccessToken();
        String refreshToken = tokenDTO.getRefreshToken();

        jwtTokenProvider.accessTokenSetHeader(accessToken, response);
        jwtTokenProvider.refreshTokenSetHeader(refreshToken, response);

        // principalDetails 객체의 정보로 DB에 접근해서 회원 정보 가져오기
        User findUser = authService.findUser(principalDetails.getUser().getId());

        // 로그인 성공시 Refresh Token Redis 저장 ( key = 유저 이름  / value = Refresh Token )
        long refreshTokenExpirationMillis = jwtTokenProvider.getRefreshTokenExpirationMillis();
        redisService.setValues(findUser.getUsername(), refreshToken, Duration.ofMillis(refreshTokenExpirationMillis));

        //this.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
        //super.successfulAuthentication(request, response, chain, authResult);
    }

}
