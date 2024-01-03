package com.example.springsecurity03.Service;

import com.example.springsecurity03.Jpa.Account;
import com.example.springsecurity03.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository repository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account byUsername = repository.findByUsername(username);

        if(byUsername == null) throw new UsernameNotFoundException("인증 실패");


        AccountContext accountContext = new AccountContext(byUsername);

        return accountContext;
    }
}
