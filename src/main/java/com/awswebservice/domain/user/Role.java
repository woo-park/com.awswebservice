package com.awswebservice.domain.user;

// inside the domain repo,

// user -> package/dir
    // User -> Entity class
    // Role -> enum class
    // UserRepository -> extended from jpa repository


import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {

    GUEST("ROLE_GUEST", "손님"),
    USER("ROLE_USER", "일반 사용자");

    private final String key;
    private final String title;

}