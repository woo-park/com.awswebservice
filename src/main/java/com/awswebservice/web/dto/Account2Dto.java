package com.awswebservice.web.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Account2Dto {
    private String username;
    private String email;
    private String password;
    //    private int age;
//    private List<String> roles;       //github
    private String userRole;
}

