package com.awswebservice.web.user;



import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MessageController {

    @GetMapping(value="/messages")
    @PreAuthorize("hasRole('MANAGER')")
    public String messages() throws Exception {

        return "user/messages";
    }
}