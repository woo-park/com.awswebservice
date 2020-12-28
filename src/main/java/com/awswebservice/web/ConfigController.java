package com.awswebservice.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ConfigController {
    @GetMapping("/config")
    public String myPage() throws Exception {

        return "admin/config";
    }


}
