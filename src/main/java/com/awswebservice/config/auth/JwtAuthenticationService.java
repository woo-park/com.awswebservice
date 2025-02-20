package com.awswebservice.config.auth;

import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.awswebservice.config.auth.security.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


@Component
public class JwtAuthenticationService {

    private static final String SECRETKEY = Base64.getEncoder().encodeToString("ProdosSecretZKey".getBytes());;

    private static final String PREFIX = "Bearer";

	private static final String EMPTY = "";

    private static final long EXPIRATIONTIME = 86400000; //1 day in milliseconds

	private static final String AUTHORIZATION = "Authorization";

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    public String createToken(String username, List<String> roles) {

        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);

        Date now = new Date();
        Date validity = new Date(now.getTime() + EXPIRATIONTIME);

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(SignatureAlgorithm.HS256, SECRETKEY)
            .compact();
    }

    public Authentication getAuthentication(HttpServletRequest request) {
    	String token = resolveToken(request);
    	if(token != null && validateToken(token)) {
    		String username = getUsername(token);
    		if(username != null) {
    			UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
    			return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    		}
    	}
        return null;
    }

    private String getUsername(String token) {
        return Jwts.parser()
        		.setSigningKey(SECRETKEY)
        		.parseClaimsJws(token)
        		.getBody().getSubject();
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith(PREFIX)) {
            return bearerToken.replace(PREFIX, EMPTY).trim();
        }
        return null;
    }

    private boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(SECRETKEY).parseClaimsJws(token);

            if (claims.getBody().getExpiration().before(new Date())) {
                return false;
            }

            return true;
        } catch (JwtException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Expired or invalid JWT token");
        }
    }
}
