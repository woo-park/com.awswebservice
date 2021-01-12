//package com.awswebservice.web;
//
////import com.awswebservice.config.auth.JwtAuthenticationService;
////import com.awswebservice.config.auth.JwtAuthenticationService;
//import com.awswebservice.config.auth.JwtAuthenticationService;
//import com.awswebservice.config.auth.dto.AccountCredentials;
//
//import com.awswebservice.domain.user.UserRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.MediaType;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.AuthenticationException;
//
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.*;
//
//import javax.servlet.http.HttpServletResponse;
//import java.util.ArrayList;
//import java.util.List;
//
//import static org.springframework.http.ResponseEntity.ok;
//
//
//@RestController
//public class AuthenticationController {
//
//    @Autowired
//    AuthenticationManager authenticationManager;
//
//    @Autowired
//    JwtAuthenticationService jwtAuthenticationService;
//
//    @Autowired
//    UserRepository userRepository;
////    consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
////    produces = {MediaType.APPLICATION_ATOM_XML_VALUE, MediaType.APPLICATION_JSON_VALUE})
////    @PostMapping("/auth/loginjwt")
//
////    @RequestMapping(value = "/auth/loginjwt", method = RequestMethod.POST, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
//    @PostMapping(
//        path = "/auth/loginjwt",
////        consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE},
//            consumes = MediaType.APPLICATION_JSON_VALUE)
//    public String signin(Model model, @RequestBody AccountCredentials credentials,  HttpServletResponse response) {
//
//        try {
//            authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword()));
//
//            List<String> list = new ArrayList<>();
//
////            list.add(this.userRepository.findByName(credentials.getUsername())
////                    .orElseThrow(
////                            () -> new UsernameNotFoundException("Username " + credentials.getUsername() + "not found"))
////                    .getRole());
//
//            list.add(this.userRepository.findByName(credentials.getUsername()).getUserRole());
//
//            String token = jwtAuthenticationService.createToken(credentials.getUsername(), list);
//            response.setHeader("Authorization", token);
////            Map<Object, Object> model = new HashMap<>();
//            model.addAttribute("username", credentials.getUsername());
//            model.addAttribute("token", token);
//            return "test";
//        } catch (AuthenticationException e) {
//            throw new BadCredentialsException("Invalid username/password supplied");
//        }
//    }
//
////    @PostMapping(
////            path = "/auth/loginjwt",
//////        consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE},
//////            MediaType.APPLICATION_JSON_VALUE,
////            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
////    public String signin2(Model model, @ModelAttribute AccountCredentials credentials,  HttpServletResponse response) {
////
////        try {
////            authenticationManager.authenticate(
////                    new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword()));
////
////            List<String> list = new ArrayList<>();
////
//////            list.add(this.userRepository.findByName(credentials.getUsername())
//////                    .orElseThrow(
//////                            () -> new UsernameNotFoundException("Username " + credentials.getUsername() + "not found"))
//////                    .getRole());
////
////            list.add(this.userRepository.findByName(credentials.getUsername()).getUserRole());
////
////            String token = jwtAuthenticationService.createToken(credentials.getUsername(), list);
////            response.setHeader("Authorization", token);
//////            Map<Object, Object> model = new HashMap<>();
////            model.addAttribute("username", credentials.getUsername());
////            model.addAttribute("token", token);
////            return "test";
////        } catch (AuthenticationException e) {
////            throw new BadCredentialsException("Invalid username/password supplied");
////        }
////    }
////
////
//
//}
