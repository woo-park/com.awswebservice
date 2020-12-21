package com.awswebservice.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {
    @GetMapping("/")
    public String home() { return "home"; }


    @GetMapping("/loginPage")
    public String loginPage() { return "loginPage"; }
}
