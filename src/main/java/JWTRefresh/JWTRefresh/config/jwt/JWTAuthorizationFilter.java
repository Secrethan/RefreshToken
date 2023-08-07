package JWTRefresh.JWTRefresh.config.jwt;

import JWTRefresh.JWTRefresh.auth.PrincipalDetails;
import JWTRefresh.JWTRefresh.domain.User;
import JWTRefresh.JWTRefresh.domain.UserDTO;
import JWTRefresh.JWTRefresh.repository.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 스프링 시큐리티 필터 중 BasicAuthenticationFilter 의 역할을 수행
// 권한, 인증이 필요한 특정 주소를 요청하였을 때 반드시 BasicAuthenticationFilter 필터를 거치게 됨
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    @Autowired
    private UserRepository userRepository;
    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        System.out.println("인증, 권한이 필요한 주소가 요청 됨 ");

        String jwtHeader = request.getHeader("Authorization");

        System.out.println("jwtHeader: " +jwtHeader);

        // header 확인
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request,response);
            return;
        }
        // 토큰 검증
        String JwtToken = request.getHeader("Authorization").replace("Bearer ","");
        System.out.println("JwtToken: "+ JwtToken);

        String username = JWT.require(Algorithm.HMAC512("ilhan_secret_key")).build().verify(JwtToken).getClaim("username").asString();
        System.out.println("username : "+username);

        // 서명 완료
        if(username != null) {
            User user = userRepository.findByUsername(username);
            System.out.println("user = " + user);

            UserDTO userDTO = UserDTO.toDTO(user);

            PrincipalDetails principalDetails = new PrincipalDetails(userDTO);

            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            //세션 저장소에 Authentication 객체 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);


            chain.doFilter(request,response);
        }
    }
}
