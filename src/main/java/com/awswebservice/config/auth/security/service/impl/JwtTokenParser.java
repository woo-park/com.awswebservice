//package com.awswebservice.config.auth.security.service.impl;
//
//import com.awswebservice.config.auth.InvalidAuthenticationTokenException;
//import com.awswebservice.config.auth.security.AuthenticationTokenDetails;
//import io.jsonwebtoken.*;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Component;
//
//import javax.validation.constraints.NotNull;
//import java.time.ZoneId;
//import java.time.ZonedDateTime;
//import java.util.ArrayList;
//import java.util.List;
//
//@Component
//public class JwtTokenParser {
//
//    @Autowired
//    private JwtSettings settings;
//
//    /**
//     * Parse a JWT token.
//     *
//     * @param token
//     * @return
//     */
//    public AuthenticationTokenDetails parseToken(String token) {
//
//        try {
//
//            Claims claims = Jwts.parser()
//                    .setSigningKey(settings.getSecret())
//                    .requireAudience(settings.getAudience())
//                    .setAllowedClockSkewSeconds(settings.getClockSkew())
//                    .parseClaimsJws(token)
//                    .getBody();
//
//            return new AuthenticationTokenDetails.Builder()
//                    .withId(extractTokenIdFromClaims(claims))
//                    .withUsername(extractUsernameFromClaims(claims))
//                    .withAuthorities(extractAuthoritiesFromClaims(claims))
//                    .withIssuedDate(extractIssuedDateFromClaims(claims))
//                    .withExpirationDate(extractExpirationDateFromClaims(claims))
//                    .withRefreshCount(extractRefreshCountFromClaims(claims))
//                    .withRefreshLimit(extractRefreshLimitFromClaims(claims))
//                    .build();
//
//        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException | SignatureException e) {
//            throw new InvalidAuthenticationTokenException("Invalid token", e);
//        } catch (ExpiredJwtException e) {
//            throw new InvalidAuthenticationTokenException("Expired token", e);
//        } catch (InvalidClaimException e) {
//            throw new InvalidAuthenticationTokenException("Invalid value for claim \"" + e.getClaimName() + "\"", e);
//        } catch (Exception e) {
//            throw new InvalidAuthenticationTokenException("Invalid token", e);
//        }
//    }
//
//    /**
//     * Extract the token identifier from the token claims.
//     *
//     * @param claims
//     * @return Identifier of the JWT token
//     */
//    private String extractTokenIdFromClaims(@NotNull Claims claims) {
//        return (String) claims.get(Claims.ID);
//    }
//
//    /**
//     * Extract the username from the token claims.
//     *
//     * @param claims
//     * @return Username from the JWT token
//     */
//    private String extractUsernameFromClaims(@NotNull Claims claims) {
//        return claims.getSubject();
//    }
//
//    /**
//     * Extract the user authorities from the token claims.
//     *
//     * @param claims
//     * @return User authorities from the JWT token
//     */
//    private String extractAuthoritiesFromClaims(@NotNull Claims claims) {
//        List<String> rolesAsString = (List<String>) claims.getOrDefault(settings.getAuthoritiesClaimName(), new ArrayList<>());
//        return rolesAsString.get(0);
//    }
//
//    /**
//     * Extract the issued date from the token claims.
//     *
//     * @param claims
//     * @return Issued date of the JWT token
//     */
//    private ZonedDateTime extractIssuedDateFromClaims(@NotNull Claims claims) {
//        return ZonedDateTime.ofInstant(claims.getIssuedAt().toInstant(), ZoneId.systemDefault());
//    }
//
//    /**
//     * Extract the expiration date from the token claims.
//     *
//     * @param claims
//     * @return Expiration date of the JWT token
//     */
//    private ZonedDateTime extractExpirationDateFromClaims(@NotNull Claims claims) {
//        return ZonedDateTime.ofInstant(claims.getExpiration().toInstant(), ZoneId.systemDefault());
//    }
//
//    /**
//     * Extract the refresh count from the token claims.
//     *
//     * @param claims
//     * @return Refresh count from the JWT token
//     */
//    private int extractRefreshCountFromClaims(@NotNull Claims claims) {
//        return (int) claims.get(settings.getRefreshCountClaimName());
//    }
//
//    /**
//     * Extract the refresh limit from the token claims.
//     *
//     * @param claims
//     * @return Refresh limit from the JWT token
//     */
//    private int extractRefreshLimitFromClaims(@NotNull Claims claims) {
//        return (int) claims.get(settings.getRefreshLimitClaimName());
//    }
//}