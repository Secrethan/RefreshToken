package JWTRefresh.JWTRefresh.service;

import JWTRefresh.JWTRefresh.domain.User;
import JWTRefresh.JWTRefresh.domain.UserDTO;

public interface AuthService {
    void logout(String refreshToken, String accessToken);

    User findUser(Integer id);

    User join(UserDTO dto);
}
