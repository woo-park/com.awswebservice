package com.awswebservice.web.admin;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ConfigController {

    @GetMapping("/config")
    @PreAuthorize("hasRole('ADMIN')")
    public String config(){
        return "admin/config";
    }
}