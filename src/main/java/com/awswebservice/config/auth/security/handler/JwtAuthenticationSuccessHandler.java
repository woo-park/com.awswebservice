package com.awswebservice.config.auth.security.handler;

import com.awswebservice.domain.user.Account;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

//        // casting되는데, principal이 어떤경우에 Account entity로 casting 가능한지 알아봐야한다.
        Account account = (Account) authentication.getPrincipal();
//
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//
////        HttpSession session = request.getSession();
////        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
//
//

        System.out.println("JWT AUTH SUCCESSFULLY DONE");
//        // 이건 확인하고 넘어가자.
        mapper.writeValue(response.getWriter(), account);
    }
}
