package io.security.security.service;

import io.security.domain.Account;
import lombok.Data;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;


public class AccountContext extends User {

    private Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(),account.getPassword(), authorities);
        this.account = account;
    }

    //getter
    public Account getAccount() {
        return account;
    }

    

}


    
