//package com.awswebservice.config.auth.security;
//
//import java.time.ZonedDateTime;
//import java.util.Collections;
//import java.util.HashSet;
//
//public final class AuthenticationTokenDetails {
//
//    private final String id;
//    private final String username;
//    private final String authorities;
//    private final ZonedDateTime issuedDate;
//    private final ZonedDateTime expirationDate;
//    private final int refreshCount;
//    private final int refreshLimit;
//
//    public String getId() {
//        return id;
//    }
//
//    public String getUsername() {
//        return username;
//    }
//
//    public String getAuthorities() {
//        return authorities;
//    }
//
//    public ZonedDateTime getIssuedDate() {
//        return issuedDate;
//    }
//
//    public ZonedDateTime getExpirationDate() {
//        return expirationDate;
//    }
//
//    public int getRefreshCount() {
//        return refreshCount;
//    }
//
//    public int getRefreshLimit() {
//        return refreshLimit;
//    }
//
//    /**
//     * Check if the authentication token is eligible for refreshment.
//     *
//     * @return
//     */
//    public boolean isEligibleForRefreshment() {
//        return refreshCount < refreshLimit;
//    }
//
//    private AuthenticationTokenDetails(String id, String username, String authorities, ZonedDateTime issuedDate, ZonedDateTime expirationDate, int refreshCount, int refreshLimit) {
//        this.id = id;
//        this.username = username;
//        this.authorities = authorities;
//        this.issuedDate = issuedDate;
//        this.expirationDate = expirationDate;
//        this.refreshCount = refreshCount;
//        this.refreshLimit = refreshLimit;
//    }
//
//    /**
//     * Builder for the {@link AuthenticationTokenDetails}.
//     */
//    public static class Builder {
//
//        private String id;
//        private String username;
//        private String authorities;
//        private ZonedDateTime issuedDate;
//        private ZonedDateTime expirationDate;
//        private int refreshCount;
//        private int refreshLimit;
//
//        public Builder withId(String id) {
//            this.id = id;
//            return this;
//        }
//
//        public Builder withUsername(String username) {
//            this.username = username;
//            return this;
//        }
//
//        public Builder withAuthorities(String authorities) {
////            this.authorities = Collections.unmodifiableSet(authorities == null ? new HashSet<>() : authorities);
//            this.authorities = authorities;
//            return this;
//        }
//
//        public Builder withIssuedDate(ZonedDateTime issuedDate) {
//            this.issuedDate = issuedDate;
//            return this;
//        }
//
//        public Builder withExpirationDate(ZonedDateTime expirationDate) {
//            this.expirationDate = expirationDate;
//            return this;
//        }
//
//        public Builder withRefreshCount(int refreshCount) {
//            this.refreshCount = refreshCount;
//            return this;
//        }
//
//        public Builder withRefreshLimit(int refreshLimit) {
//            this.refreshLimit = refreshLimit;
//            return this;
//        }
//
//        public AuthenticationTokenDetails build() {
//            return new AuthenticationTokenDetails(id, username, authorities, issuedDate, expirationDate, refreshCount, refreshLimit);
//        }
//    }
//}