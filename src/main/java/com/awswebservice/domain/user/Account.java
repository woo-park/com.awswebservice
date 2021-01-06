package com.awswebservice.domain.user;


//import com.awswebservice.domain.BaseTimeEntity;

import lombok.*;

import javax.persistence.*;
import com.awswebservice.domain.user.Role;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;


//@Setter
//@Getter
//@Entity
//public class User{
//
//    /**
//     *
//     */
//    private static final long serialVersionUID = 1L;
//    @Id
//    @GeneratedValue(strategy = GenerationType.AUTO)
//    @Column(nullable = false, updatable = false)
//    private Long userid;
//
//    @Column( nullable = false)
//    private String username;
//
//    @Column(nullable = false, unique = true)
//    private String email;
//
//    @Column( nullable = false)
//    private String password;
//
//    @Column(nullable = false)
//    @Enumerated(EnumType.STRING)
//    private Role role;
//
//    @Column(nullable = false)
//    private String accountRole;
//
//    @Builder
//    public User(String username, String email, String password, Role role) { //using the private field variables
//        this.username = username;
//        this.email = email;
//        this.password = password;
//        this.role = role;
//    }                       // now you have .save and .etc methods provided by lombok
//
//    public User update(String username) {
//        this.username = username;
//        return this;
//    }
//
//    public String getRoleKey() {
//        return this.role.getKey();
//    }

//    @Override
//    public String toString() {
//        return "User [userid=" + userid + ", username=" + username + ", email="
//                + email + ", password=" + password + ", role=" + role + "]";
//    }

//    @Override
//    public int hashCode() {
//        final int prime = 31;
//        int result = 1;
//        result = prime * result + ((email == null) ? 0 : email.hashCode());
//        result = prime * result
//                + ((password == null) ? 0 : password.hashCode());
//        result = prime * result + ((role == null) ? 0 : role.hashCode());
//        result = prime * result + ((userid == null) ? 0 : userid.hashCode());
//        result = prime * result
//                + ((username == null) ? 0 : username.hashCode());
//        return result;
//    }
//    @Override
//    public boolean equals(Object obj) {
//        if (this == obj)
//            return true;
//        if (obj == null)
//            return false;
//        if (getClass() != obj.getClass())
//            return false;
//        User other = (User) obj;
//        if (email == null) {
//            if (other.email != null)
//                return false;
//        } else if (!email.equals(other.email))
//            return false;
//        if (password == null) {
//            if (other.password != null)
//                return false;
//        } else if (!password.equals(other.password))
//            return false;
//        if (role != other.role)
//            return false;
//        if (userid == null) {
//            if (other.userid != null)
//                return false;
//        } else if (!userid.equals(other.userid))
//            return false;
//        if (username == null) {
//            if (other.username != null)
//                return false;
//        } else if (!username.equals(other.username))
//            return false;
//        return true;
//    }


//}
//@ToString(exclude = {"userRoles"})
//@Getter
//@Setter
//@NoArgsConstructor
//@AllArgsConstructor
//@Builder
//@Entity
//public class Account implements Serializable {
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private long id;
//
//    @Column(nullable = false)
//    private String name;
//
//    @Column(nullable = false)
//    private String email;
//
//
//    @Column(nullable = true)
//    private String userRoles;
//
//    @Column
//    private String password;
//
//}



//}
//@ToString(exclude = {"userRoles"})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Account implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String email;


    @Column(nullable = true)
    private String picture;     //not sure how picture is a string

    @Enumerated(EnumType.STRING)
    @Column(nullable = true)       //empty false
    private Role role;


    @Column(nullable = true)
    private String userRoles;

    @Column(nullable = true)
    private String userRole;

    @Column(nullable = true)
    private String password;


    @Builder
    public Account(String name, String email, String picture, String userRole) { //using the private field variables
        this.name = name;
        this.email = email;
        this.picture = picture;
//        this.role = role;
        this.userRole = userRole;
    }                       // now you have .save and .etc methods provided by lombok


    public Account update(String name, String picture) {
        this.name = name;
        this.picture = picture;

        return this;
    }

    // Role을 사용할적에 사용했었습니다.
//    public String getRoleKey() {
//        return this.role.getKey();
//    }
}

