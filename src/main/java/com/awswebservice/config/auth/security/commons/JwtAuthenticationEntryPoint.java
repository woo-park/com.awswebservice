package com.awswebservice.config.auth.security.commons;

import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {
    private static final long serialVersionUID = -8970718410437077606L;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // This is invoked when user tries to access a secured REST resource without supplying any credentials
        // We should just send a 401 Unauthorized response because there is no 'login page' to redirect to
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }



    // cassiomolin
//    @Override
//    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//
//        HttpStatus status;
//        ApiErrorDetails errorDetails = new ApiErrorDetails();
//
//        if (authException instanceof InvalidAuthenticationTokenException) {
//            status = HttpStatus.UNAUTHORIZED;
//            errorDetails.setTitle(authException.getMessage());
//            errorDetails.setMessage(authException.getCause().getMessage());
//        } else {
//            status = HttpStatus.FORBIDDEN;
//            errorDetails.setTitle(status.getReasonPhrase());
//            errorDetails.setMessage(authException.getMessage());
//        }
//
//        errorDetails.setStatus(status.value());
//        errorDetails.setPath(request.getRequestURI());
//
//        response.setStatus(status.value());
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//
//        mapper.writeValue(response.getWriter(), errorDetails);
//    }
}

