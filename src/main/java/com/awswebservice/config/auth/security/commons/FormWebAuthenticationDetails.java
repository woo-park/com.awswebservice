package com.awswebservice.config.auth.security.commons;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key");
    }

    public String getSecretKey() {
        return secretKey;
    }
}
//https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/WebAuthenticationDetails.html#WebAuthenticationDetails-javax.servlet.http.HttpServletRequest-