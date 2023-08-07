package JWTRefresh.JWTRefresh.config.jwt;


import JWTRefresh.JWTRefresh.auth.PrincipalDetails;
import JWTRefresh.JWTRefresh.domain.UserDTO;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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
import java.util.Date;

// extends UsernamePasswordAuthenticationFilter
// /login 을 요청해서 username,pw를 전송하면 UsernamePasswordAuthenticationFilter 필터가 동작하지만 formLogin().disable() 설정 때문에 동작하지 않음
//
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JWTAuthenticationFilter : 진입 ");

        ObjectMapper om = new ObjectMapper();
        UserDTO userDTO = null;
        // username, password 받음
        // 로그인 시도 -> authenticationManager 를 통해 로그인 시도 하면 PrincipalDetailsService 호출, loadUserByUsername 메서드 실행을 통해 인증을 수행하고 PrincipalDetails 객체를 만듦
        // PrincipalDetails 를 세션에 담아(권한 관리를 위해) JWT 토큰을 만들어 클라이언트에 보내줌
        try {
            //Json 문자열을 UserDTO 클래스의 객체로 반환
            userDTO = om.readValue(request.getInputStream(), UserDTO.class);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        // 인증 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDTO.getUsername(), userDTO.getPassword());
        // PrincipalDetails Service 의 loadUserByUsername() 메서드가 실행됨
        // 토큰을 생성할 때 사용된 username 사용
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        //인증 완료시 session 저장소 내에 authentication 객체가 저장되어 principalDetails 객체에 담긴 사용자 정보를 확인할 수 있다.
        System.out.println("principalDetails.getUsername() = " + principalDetails.getUser().getUsername());

        // 로그인한 정보가 authentication 에 담겨서 session 저장소에 저장
        // JWT 토큰을 사용하면서 굳이 세션을 만들 이유는 없지만 세션을 사용하면 권한 처리를 security 가 대신 해주어 편리하기 때문에 사용

        return authentication;
    }
    //  attemptAuthentication 메서드를 통해 정상적으로 인증이 완료되면 successfulAuthentication 메서드가 실행됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행 : 인증 완료 ");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // header + payload + signature
        // header : 토큰 타입 + 해싱 알고리즘
        // payload : 클레임(공개, 비공개) - Subject, Expire 등과 같은 토큰에 담을 정보
        // signature : 헤더 + 정보를 합친 후 비밀 키와 함께 헤더에서 정의한 해싱 알고리즘을 통해 암호화
        String jwtToken = JWT.create()
                .withSubject("JWT_Token")
                 // 만료 시간 (현재 시간 + 10분)
                .withExpiresAt(new Date(System.currentTimeMillis()+ (60000 * 10)))
                 // 회원 구분 - id
                .withClaim("id", principalDetails.getUser().getId())
                 // 회원 구부 - username
                .withClaim("username", principalDetails.getUser().getUsername())
                 // 해싱 알고리즘, 비밀키
                .sign(Algorithm.HMAC512("ilhan_secret_key"));

        System.out.println("jwtToken = " + jwtToken);

        response.addHeader("Authorization", "Bearer "+jwtToken);

        super.successfulAuthentication(request, response, chain, authResult);
    }


}
