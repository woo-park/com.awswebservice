//package com.awswebservice.config.auth.security.provider;
//
//import com.awswebservice.config.auth.security.AuthenticationTokenDetails;
//import com.awswebservice.config.auth.security.service.AccountContext;
////import com.awswebservice.config.auth.security.token.AjaxAuthenticationToken;
//import com.awswebservice.config.auth.security.service.AuthenticationTokenService;
//import com.awswebservice.config.auth.security.token.JwtAuthenticationToken;
//import io.jsonwebtoken.*;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//import javax.annotation.PostConstruct;
//import javax.servlet.http.HttpServletRequest;
//import javax.transaction.Transactional;
//import java.util.Base64;
//import java.util.Date;
//import java.util.List;
//
//
//// cassiomolin
//
//public class JwtAuthenticationProvider implements AuthenticationProvider {
//
//    @Autowired
//    private UserDetailsService userDetailsService;
//
//    @Autowired
//    private AuthenticationTokenService authenticationTokenService;
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//
//        String authenticationToken = (String) authentication.getCredentials();
//        AuthenticationTokenDetails authenticationTokenDetails = authenticationTokenService.parseToken(authenticationToken);
//        UserDetails userDetails = this.userDetailsService.loadUserByUsername(authenticationTokenDetails.getUsername());
//
//        return new JwtAuthenticationToken(userDetails, authenticationTokenDetails, userDetails.getAuthorities());
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
//    }
//}
//
//
//
///*
//
//public class JwtAuthenticationProvider implements AuthenticationProvider {
//
//    @Value("${security.jwt.token.secret-key:secret}")
//    private String secretKey = "secret";
//
//    @Value("${security.jwt.token.expire-length:3600000}")
//    private long validityInMilliseconds = 3600000; // 1h
//
//
//    @Autowired
//    private UserDetailsService userDetailsService;
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Override
//    @Transactional
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//
//        String loginId = authentication.getName();
//        String password = (String) authentication.getCredentials();
//
//        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(loginId);
//
//        if (!passwordEncoder.matches(password, accountContext.getPassword())) {
//            throw new BadCredentialsException("Invalid password");
//        }
//
//        return new JwtAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
//    }
//
//
//
//    //cassiomolin
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        String authenticationToken = (String) authentication.getCredentials();
//        AuthenticationTokenDetails authenticationTokenDetails = authenticationTokenService.parseToken(authenticationToken);
//        UserDetails userDetails = this.userDetailsService.loadUserByUsername(authenticationTokenDetails.getUsername());
//        return new JwtAuthenticationToken(userDetails, authenticationTokenDetails, userDetails.getAuthorities());
//    }
//
//
//
//
//
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return authentication.equals(JwtAuthenticationToken.class);
//    }
//
//
//
//
//
////    @Autowired
////    private UserDetailsService userDetailsService;
//
//    @PostConstruct
//    protected void init() {
//        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
//    }
//
//    public String createToken(String username, List<String> roles) {
//
//        Claims claims = Jwts.claims().setSubject(username);
//        claims.put("roles", roles);
//
//        Date now = new Date();
//        Date validity = new Date(now.getTime() + validityInMilliseconds);
//
//        return Jwts.builder()//
//                .setClaims(claims)//
//                .setIssuedAt(now)//
//                .setExpiration(validity)//
//                .signWith(SignatureAlgorithm.HS256, secretKey)//
//                .compact();
//    }
//
//    public Authentication getAuthentication(String token) {
//        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUsername(token));
//        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
//    }
//
//    public String getUsername(String token) {
//        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
//    }
//
//    public String resolveToken(HttpServletRequest req) {
//        String bearerToken = req.getHeader("Authorization");
//        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
//            return bearerToken.substring(7, bearerToken.length());
//        }
//        return null;
//    }
//
//    public boolean validateToken(String token) {
//        try {
//            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
//
//            if (claims.getBody().getExpiration().before(new Date())) {
//                return false;
//            }
//
//            return true;
//        } catch (JwtException | IllegalArgumentException e) {
////            return
//            throw new IllegalArgumentException("Expired or invalid JWT token");
//        }
//    }
//
//
//
//
//}
//
//
//*/