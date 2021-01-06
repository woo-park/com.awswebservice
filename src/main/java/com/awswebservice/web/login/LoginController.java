package com.awswebservice.web.login;


import com.awswebservice.domain.user.Account;
import com.awswebservice.web.dto.AccountDto;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

@Controller
public class LoginController {

    @RequestMapping(value="/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception, Model model){
        model.addAttribute("error",error);
        model.addAttribute("exception",exception);


        return "login";
    }

    @GetMapping(value = "/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) throws Exception {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null){
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }

    @GetMapping(value="/denied")
    public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Principal principal, Model model) throws Exception {

        Account account = null;

        if (principal instanceof UsernamePasswordAuthenticationToken) {
            account = (Account) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();

        }
        if (principal instanceof OAuth2AuthenticationToken) {
            Object userDetailsTest = (Object)((OAuth2AuthenticationToken) principal).getPrincipal();

//            account = (Account) ((OAuth2AuthenticationToken) principal).getPrincipal();

//            AccountDto accountPrincipal = (AccountDto) ((OAuth2AuthenticationToken) principal).getPrincipal();
            account = Account.builder().build();
//            account = (Account) ((OAuth2AuthenticationToken) principal).getPrincipal();
        }
//        else if(principal instanceof AjaxAuthenticationToken){
//            account = (Account) ((AjaxAuthenticationToken) principal).getPrincipal();
//        }


        if(account != null) {
            model.addAttribute("username", account.getName());
            model.addAttribute("exception", exception);
            model.addAttribute("name", account.getName());

        }

        return "user/login/denied";
    }
}