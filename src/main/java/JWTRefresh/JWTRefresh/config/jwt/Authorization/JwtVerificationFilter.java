package JWTRefresh.JWTRefresh.config.jwt.Authorization;

import JWTRefresh.JWTRefresh.config.jwt.JwtTokenProvider;
import JWTRefresh.JWTRefresh.service.RedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JwtVerificationFilter extends OncePerRequestFilter {
    // 인증에서 제외할 url
    private static final List<String> EXCLUDE_URL =
            List.of("/",
                    "/h2",
                    "/members/signup",
                    "/auth/login",
                    "/auth/reissue");
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;

    // JWT 인증 정보를 현재 쓰레드의 SecurityContext 에 저장 (회원 가입, 로그인, 재발급 Request 제외)
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        /*
            resolveAccessToken(request) : request header 에 Access Token 정보를 추출하는 메서드
            StringUtils.hasText(accessToken) : accessToken 존재 확인
            doNotLogout(accessToken) : 로그아웃 처리한 accessToken 인지 확인
            jwtTokenProvider.validateToken(accessToken, response) : 토큰 검증
         */
        try{
            String accessToken = jwtTokenProvider.resolveAccessToken(request);
            if(StringUtils.hasText(accessToken) && doNotLogout(accessToken) && jwtTokenProvider.validateToken(accessToken, response)) {
                setAuthenticationToContext(accessToken);
                System.out.println("success !");
            }
        } catch (RuntimeException e) {
            e.printStackTrace();
        }
          filterChain.doFilter(request, response);
    }
    private boolean doNotLogout(String accessToken) {
        String isLogout = redisService.getValues(accessToken);
        return isLogout.equals("false");
    }
    // 인증에서 제외한 EXCLUDE_URL 이 요청으로 들어올 경우 바로 다음 필터 진행
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        boolean result = EXCLUDE_URL.stream().anyMatch(exclude -> exclude.equalsIgnoreCase(request.getServletPath()));

        return result;
    }
    private void setAuthenticationToContext(String accessToken) {
        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        System.out.println("# Token verification success!");
    }

}
