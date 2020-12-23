package com.awswebservice.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {
    @GetMapping("/")
    public String home() {
        return "home";
    }


    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }
    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    //강의 12)
    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }
//    @GetMapping("/login")
//    public String login() {
//        return "login";
//    }

}
