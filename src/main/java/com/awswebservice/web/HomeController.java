package com.awswebservice.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping(value="/")
    public String home() throws Exception {
        return "home";
    }

}