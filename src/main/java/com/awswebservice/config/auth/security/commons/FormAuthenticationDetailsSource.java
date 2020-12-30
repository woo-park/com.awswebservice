package com.awswebservice.config.auth.security.commons;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

@Component
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest context) {

        return new FormWebAuthenticationDetails(context);
//        return null;
    }
}


/*
*
* 결국,
* AuthenticationDetailsSource가 buildDetails Method를 통해서, (parameter로 HttpServletRequest context를 넘긴후)
* buildMethod가 WebAuthenticationDetails를 만든다, (여기선 new FormWebAuthenticationDetails(context);
*
* 이렇게하면
* user -> request보내고 -> AuthenticationFilter에서 받은후 -> Authentication객체(details)를 생성후 -> WebAuthenticationDetails을통해, remoteAddress, SessionId, request.getParameter("param1")이렇게 꺼내 받을수있다.
*
*
* */


