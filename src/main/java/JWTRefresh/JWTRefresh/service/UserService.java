package JWTRefresh.JWTRefresh.service;

import JWTRefresh.JWTRefresh.domain.User;
import JWTRefresh.JWTRefresh.domain.UserDTO;

public interface UserService  {
    User Join(UserDTO dto);
    User findUser(Integer id);
}
