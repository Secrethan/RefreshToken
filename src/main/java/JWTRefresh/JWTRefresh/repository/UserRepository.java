package JWTRefresh.JWTRefresh.repository;

import JWTRefresh.JWTRefresh.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {

    //select * from user where username = {}
    public User findByUsername(String username);

}
