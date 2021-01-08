//package com.awswebservice.web.jwt;
//
//
//import com.awswebservice.config.auth.security.provider.JwtAuthenticationProvider;
//import com.awswebservice.domain.user.UserRepository;
//import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
//import com.nimbusds.openid.connect.sdk.ClaimsRequest;
//import io.jsonwebtoken.Claims;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//import java.util.HashMap;
//import java.util.Map;
//
//@RestController
//@RequestMapping("/auth")
//public class AuthController {
//
//    @Autowired
//    AuthenticationManager authenticationManager;
//
////    @Autowired
//    JwtAuthenticationProvider jwtTokenProvider;
//
//    @Autowired
//    UserRepository users;
//
////    @PostMapping("/signin")
////    public ResponseEntity signin(@RequestBody AuthenticationRequest data, Model model) {
////
////        try {
//////            ClaimsRequest username = data.getClaims();
////            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, data.getPassword()));
////            String token = jwtTokenProvider.createToken(username, this.users.findByName(username).orElseThrow(() -> new UsernameNotFoundException("Username " + username + "not found")).getRoles());
////
////            model.addAttribute("username", username);
////            model.addAttribute("token", token);
////
////            return "home";
////        } catch (AuthenticationException e) {
////            throw new BadCredentialsException("Invalid username/password supplied");
////        }
////    }
//}