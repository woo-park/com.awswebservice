package com.awswebservice.service;


import com.awswebservice.domain.prodosUser.ProdosUser;
import com.awswebservice.domain.prodosUser.ProdosUserRepository;
//import com.awswebservice.domain.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private ProdosUserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        ProdosUser prodosUser = userRepository.findByUsername(username).get();
        UserDetails user = new User(username, prodosUser.getPassword(), AuthorityUtils.createAuthorityList(prodosUser.getRole()));
        return user;
    }

}
