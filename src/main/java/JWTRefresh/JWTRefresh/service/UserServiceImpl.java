package JWTRefresh.JWTRefresh.service;

import JWTRefresh.JWTRefresh.domain.User;
import JWTRefresh.JWTRefresh.domain.UserDTO;
import JWTRefresh.JWTRefresh.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@Service

public class UserServiceImpl implements UserService{
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder encoder;


    @Override
    public User Join(UserDTO dto) {
        String rawPassword = dto.getPassword();
        String encPassword = encoder.encode(rawPassword);
        dto.setPassword(encPassword);
        User user = User.toEntity(dto);
        return userRepository.save(user);
    }
}
