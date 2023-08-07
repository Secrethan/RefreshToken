package JWTRefresh.JWTRefresh.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.sql.Timestamp;

@Entity
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // orcale sequence 처럼 DB에 저장할 때 생성
    private int id;
    private String username;
    @JsonIgnore // Json 변환시 password 제외
    private String password;
    private String role;
    @CreationTimestamp //Insert, Update 쿼리가 발생할 때 현재 시간을 자동으로 저장해주는 어노테이션
    private Timestamp date;


    public static User toEntity(UserDTO dto) {
        return User.builder()
                .id(dto.getId())
                .username(dto.getUsername())
                .password(dto.getPassword())
                .role(dto.getRole())
                .build();
    }

}
