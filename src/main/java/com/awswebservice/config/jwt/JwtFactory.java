//package com.awswebservice.config.jwt;
//
//import com.auth0.jwt.algorithms.Algorithm;
//import lombok.RequiredArgsConstructor;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.stereotype.Component;
//
//import com.auth0.jwt.JWT;
//
//import java.io.UnsupportedEncodingException;
//import java.util.Date;
//
//// import 생략
//
//@RequiredArgsConstructor
//@Component
//public class JwtFactory { // aka JwtTokenProvider JWT 토큰을 생성 및 검증 모듈
//    private static final Logger log = LoggerFactory.getLogger(JwtFactory.class);
//    // 2.
//    private static String signingKey = "jwttest";
//
//    // 1.
//    public String generateToken(AccountContext account) {
//        String token = null;
//        try {
//            token = JWT.create()
//                    .withIssuer("wooinabillion")
//                    .withClaim("USERNAME", account.getAccount().getUserId())
//                    .withClaim("USER_ROLE", account.getAccount().getUserRole().getKey())
//                    .withClaim("EXP", new Date(System.currentTimeMillis() + 864000000))
//                    .sign(generateAlgorithm());
//        } catch(Exception e) {
//            e.printStackTrace();
//            log.error(e.getMessage());
//        }
//
//        return token;
//    }
//
//    // 2.
//    private Algorithm generateAlgorithm() throws UnsupportedEncodingException {
//        return Algorithm.HMAC256(signingKey);
//    }
//
//
//}