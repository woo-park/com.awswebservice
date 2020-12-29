package com.awswebservice.config.auth.security;

import com.awswebservice.domain.user.Account;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
public class AccountContext extends User {
    private final Account account;


    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getName(), account.getPassword(), authorities);
        this.account = account;
    }
}
