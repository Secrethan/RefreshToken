package JWTRefresh.JWTRefresh.auth;

import JWTRefresh.JWTRefresh.domain.User;
import JWTRefresh.JWTRefresh.domain.UserDTO;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

@Data
@NoArgsConstructor
public class PrincipalDetails implements UserDetails {

    private UserDTO userDTO;

    public PrincipalDetails(UserDTO userDTO) {
        this.userDTO = userDTO;
    }
    public PrincipalDetails(String username, String role) {
        this.userDTO = new UserDTO();
        this.userDTO.setRole(role);
        this.userDTO.setUsername(username);
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Collection<? extends GrantedAuthority> 타입으로 반환
        Collection<GrantedAuthority> collect = new ArrayList<>();
        //자바는 GrantedAuthority 객체를 담을 수는 있지만 가져올 수 없기 때문에 재정의
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return userDTO.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return userDTO.getPassword();
    }

    @Override
    public String getUsername() {
        return userDTO.getUsername();
    }
    public UserDTO getUser(){
        return userDTO;
    }
    public String getRole(){
        return userDTO.getRole();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
