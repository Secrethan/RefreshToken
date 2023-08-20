package JWTRefresh.JWTRefresh.service;

import JWTRefresh.JWTRefresh.auth.PrincipalDetails;
import JWTRefresh.JWTRefresh.config.jwt.JwtTokenProvider;
import JWTRefresh.JWTRefresh.domain.TokenDTO;
import JWTRefresh.JWTRefresh.domain.User;
import JWTRefresh.JWTRefresh.domain.UserDTO;
import JWTRefresh.JWTRefresh.repository.AuthRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;
    private final BCryptPasswordEncoder encoder;
    private final AuthRepository authRepository;

    @Override
    public User findUser(Integer id) {
       return authRepository.findById(id).orElseThrow(() -> {
           return new IllegalArgumentException("User ID를 찾을 수 없습니다.");
       });
    }
    @Override
    public User join(UserDTO dto){
        StringBuilder sb = new StringBuilder();
        String encPassword= encoder.encode(sb.append(dto.getPassword()).toString());

        dto.setPassword(encPassword);
        User user = User.toEntity(dto);
        return authRepository.save(user);
    }
    @Override
    public void logout(String refreshToken, String accessToken) {
        /*
            1. request 로 전달받은 refreshToken null 여부 확인
            2. null 이 아니라면 Claims 객체를 파싱
            3. claims 의 subject 로 설정했던 username 을 조회
            4. redis 에서 username 을 value 로 갖고 있는 refreshToken 조회
            5. 존재한다면 redis 에서 삭제
            6. redis 에서 accessToken 을 블랙리스트 처리
         */
        this.verifiedRefreshToken(refreshToken);

        Claims claims = jwtTokenProvider.parseClaims(refreshToken);
        System.out.println("claims : " + claims);
        String username = claims.getSubject();
        System.out.println("username : "+ username);
        String redisRefreshToken = redisService.getValues(username);

        if(redisService.checkExistsValue(redisRefreshToken)) {
            redisService.deleteValues(username);
        }
        long accessTokenExpirationMillis = jwtTokenProvider.getAccessTokenExpirationMillis();

        redisService.setValues(accessToken, "logout", Duration.ofMillis(accessTokenExpirationMillis));

    }
    private void verifiedRefreshToken(String refreshToken) {
        if (refreshToken == null) {
            System.out.println("리프레시 토큰 없다. ");
        }
    }

    @Override
    public String reissueAccessToken(String refreshToken) {
        this.verifiedRefreshToken(refreshToken);

        Claims claims = jwtTokenProvider.parseClaims(refreshToken);
        String username = claims.getSubject();
        String redisRefreshToken = redisService.getValues(username);

        if (redisService.checkExistsValue(redisRefreshToken) && redisRefreshToken.equals(redisRefreshToken)) {
            User findUser = authRepository.findByUsername(username);
            UserDTO dto = UserDTO.toDTO(findUser);
            PrincipalDetails principalDetails = new PrincipalDetails(dto);

            TokenDTO tokenDTO = jwtTokenProvider.generateTokenDTO(principalDetails);
            String newAccessToken = tokenDTO.getAccessToken();
            long refreshTokenExpirationMillis = jwtTokenProvider.getRefreshTokenExpirationMillis();

            return newAccessToken;
        }
        else throw new NullPointerException("AccessToken_NOT_EXISTS");
    }

}
