//package com.awswebservice.config.auth.security.service;
//
//import com.awswebservice.config.auth.security.service.AccountContext;
//import com.awswebservice.domain.user.Account;
//import com.awswebservice.domain.user.UserRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//
//import java.util.ArrayList;
//import java.util.List;
//
//// UserDetailsServiceImpl과 identical
//
//@Service("userDetailsService")
//public class CustomUserDetailsService implements UserDetailsService {
//    @Autowired
//    private UserRepository userRepository;
//
//    @Override
//    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
//        Account account = userRepository.findByName(name);
//
//        if(account == null) {
//            throw new UsernameNotFoundException("UsernameNotFoundException");
//        }
//
//        List<GrantedAuthority> roles = new ArrayList<>();
//        roles.add(new SimpleGrantedAuthority(account.getUserRole()));
//
//        AccountContext accountContext = new AccountContext(account, roles);
//        return accountContext;
//    }
//}
