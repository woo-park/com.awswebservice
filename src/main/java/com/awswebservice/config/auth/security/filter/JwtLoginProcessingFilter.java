//package com.awswebservice.config.auth.security.filter;
//
//import com.awswebservice.config.auth.security.token.AjaxAuthenticationToken;
//import com.awswebservice.util.WebUtil;
//import com.awswebservice.web.dto.Account2Dto;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.authentication.AuthenticationServiceException;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//import org.springframework.util.StringUtils;
//
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//
//public class JwtLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
//
//    private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
//    private static final String X_REQUESTED_WITH = "X-Requested-With";
//
//    private ObjectMapper objectMapper = new ObjectMapper();
//    public JwtLoginProcessingFilter() {
//        super(new AntPathRequestMatcher("/api/login", "POST"));
//    }
//
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
//            throws AuthenticationException, IOException {
//
//        if (!isJwt(request)) {
//            throw new IllegalStateException("Authentication is not supported");
//        }
//
////        if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
////            throw new IllegalArgumentException("Authentication method not supported");
////        }
//
//        Account2Dto account2Dto = objectMapper.readValue(request.getReader(), Account2Dto.class);
//
//        System.out.println("pause");
//        if (StringUtils.isEmpty(account2Dto.getUsername()) || StringUtils.isEmpty(account2Dto.getPassword())) {
//            throw new AuthenticationServiceException("Username or Password is empty");
//        }
//        AjaxAuthenticationToken token = new AjaxAuthenticationToken(account2Dto.getUsername(),account2Dto.getPassword());
//
//        return this.getAuthenticationManager().authenticate(token);
//    }
//
//    private boolean isJwt(HttpServletRequest request) {
////        if("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
//            return true;
////        }
////        return false;
//    }
//
//
//    String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
//    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
//
//        try {
//
//            String authenticationToken = authorizationHeader.substring(7);
//            Authentication authenticationRequest = new JwtAuthenticationToken(authenticationToken);
//            Authentication authenticationResult = authenticationManager.authenticate(authenticationRequest);
//
//            SecurityContext context = SecurityContextHolder.createEmptyContext();
//            context.setAuthentication(authenticationResult);
//            SecurityContextHolder.setContext(context);
//
//        } catch (AuthenticationException e) {
//            SecurityContextHolder.clearContext();
//            authenticationEntryPoint.commence(request, response, e);
//            return;
//        }
//    }
//
//
//
//
//
//
//}
//
//
