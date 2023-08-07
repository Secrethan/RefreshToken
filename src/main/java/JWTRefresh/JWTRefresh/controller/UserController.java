package JWTRefresh.JWTRefresh.controller;


import JWTRefresh.JWTRefresh.domain.UserDTO;
import JWTRefresh.JWTRefresh.response.Response;
import JWTRefresh.JWTRefresh.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

// Jackson 존재하면 JSON 형식의 문자열로 변환해서 응답한다.
@RestController
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("/join")
    public Response<?> join(@RequestBody String userData) {
        ObjectMapper om = new ObjectMapper();
        UserDTO dto = null;
        try{
            dto = om.readValue(userData, UserDTO.class);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return new Response<>("true","회원 가입 성공",userService.Join(dto));
    }

    @GetMapping("/user/{id}")
    public Response<?> findUser(@PathVariable("id") Integer id) {
        System.out.println(id);
        return new Response<>("true","조회 성공",userService.findUser(id));
    }

    @PostMapping("/user/test")
    public String test1() {
        return "ROLE_USER / ADMIN 접근 가능";
    }
    @PostMapping("/admin/test")
    public String test2() {
        return "ADMIN 접근 가능";
    }


}