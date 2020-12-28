package com.awswebservice.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class UserController {
    @GetMapping("/mypage")
    public String myPage() throws Exception {

        return "user/mypage";
    }


}
