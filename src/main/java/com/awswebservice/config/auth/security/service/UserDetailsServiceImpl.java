package com.awswebservice.config.auth.security.service;//package com.awswebservice.service;


import com.awswebservice.config.auth.security.service.AccountContext;
import com.awswebservice.domain.prodosUser.ProdosUser;
import com.awswebservice.domain.prodosUser.ProdosUserRepository;
import com.awswebservice.domain.user.Account;
import com.awswebservice.domain.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


// prodos
//@Service
//public class UserDetailServiceImpl implements UserDetailsService {
//
//    @Autowired
//    private ProdosUserRepository userRepository;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//
//        ProdosUser prodosUser = userRepository.findByUsername(username).get();
//        UserDetails user = new User(username, prodosUser.getPassword(), AuthorityUtils.createAuthorityList(prodosUser.getRole()));
//        return user;
//    }
//
//}




// onjsdnjs

@Slf4j
@Service("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

//    @Autowired
//    private HttpServletRequest request;

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account account = userRepository.findByName(username);
        if (account == null) {
            if (userRepository.countByName(username) == 0) {
                throw new UsernameNotFoundException("No user found with username: " + username);
            }
        }

//        roles가 entity가 아닌 String 이기때문에
//        Set<String> userRoles = account.getUserRoles()
//                .stream()
//                .map(userRole -> userRole.getRoleName())
//                .collect(Collectors.toSet());
//        List<GrantedAuthority> collect = userRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getUserRole()));

        return new AccountContext(account, roles);
    }
}