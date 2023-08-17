package JWTRefresh.JWTRefresh.config.jwt.Authorization;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

// 인증 예외 처리 ( 401 )
@Component
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // 유효한 자격 증명 (토큰) 을 제공하지 않고 접근할 때
        // Ex) user 자격으로 admin 에 허용하는 리소스에 접근하려할 때 , 아예 자격 증명이 되지 않을떄
        // 인증 단계, 권한 부여 단계 중 어디에 적합할지 헷갈린다..
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding("UTF-8");
        PrintWriter pw = response.getWriter();
        pw.println("{\"error\": \"NO_AUTHORIZATION\", \"message\" : \"인증정보가 없습니다.\"}");


    }
}
