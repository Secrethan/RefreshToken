package JWTRefresh.JWTRefresh.controller;

import JWTRefresh.JWTRefresh.domain.UserDTO;

import JWTRefresh.JWTRefresh.response.Response;
import JWTRefresh.JWTRefresh.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "home/loginForm";
    }
    @GetMapping("/joinForm")
    public String loginForm() {

        return "home/joinForm";
    }





}
