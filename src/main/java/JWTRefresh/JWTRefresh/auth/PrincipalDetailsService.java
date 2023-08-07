package JWTRefresh.JWTRefresh.auth;

import JWTRefresh.JWTRefresh.domain.User;
import JWTRefresh.JWTRefresh.domain.UserDTO;
import JWTRefresh.JWTRefresh.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        System.out.println("loadUserByUsername 실행");

        if(username != null) {
            UserDTO dto = UserDTO.toDTO(user);
            return new PrincipalDetails(dto);
        }
        else {
            System.out.println("일치하는 회원 정보가 없습니다.");
        }
        return null;
    }
}
