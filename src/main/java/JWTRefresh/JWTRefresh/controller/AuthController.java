package JWTRefresh.JWTRefresh.controller;

import JWTRefresh.JWTRefresh.config.jwt.JwtTokenProvider;
import JWTRefresh.JWTRefresh.domain.UserDTO;
import JWTRefresh.JWTRefresh.response.Response;
import JWTRefresh.JWTRefresh.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    /*
        회원 목록 조회     GET         /auth
        회원 등록        POST        /auth
        회원 조회        GET         /auth/{userId}
        회원 수정        PATCH       /auth{userId}
        로그인          POST        /auth/login
        로그아웃        PATCH       /auth/logout
     */
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthService authService;
    @ApiOperation(value = "회원 가입", notes = "회원가입 한다.")
    @PostMapping("")
    public Response<?> join(@RequestBody String userData) {
        ObjectMapper om = new ObjectMapper();
        UserDTO user = null;

        try{
            user = om.readValue(userData, UserDTO.class);
        }catch (Exception e) {
            e.printStackTrace();
        }
        return new Response<>("true","회원 가입 성공",authService.join(user));
    }

    @ApiOperation(value = "로그 아웃", notes = "로그아웃 한다. ")
    @PatchMapping("/logout")
    public ResponseEntity logout(HttpServletRequest request){
        String refreshToken = jwtTokenProvider.resolveRefreshToken(request);
        String accessToken = jwtTokenProvider.resolveAccessToken(request);

        authService.logout(refreshToken,accessToken);

        return new ResponseEntity("success", HttpStatus.OK);
    }


}
