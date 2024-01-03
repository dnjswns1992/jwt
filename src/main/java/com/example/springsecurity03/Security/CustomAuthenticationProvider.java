//package com.example.springsecurity03.Security;
//
//import com.example.springsecurity03.Commom.FormWebAuthenticationDetails;
//import com.example.springsecurity03.Jpa.Account;
//import com.example.springsecurity03.Repository.UserRepository;
//import com.example.springsecurity03.Service.AccountContext;
//import lombok.RequiredArgsConstructor;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.InsufficientAuthenticationException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//@Component
//public class CustomAuthenticationProvider implements AuthenticationProvider {
//
//    public CustomAuthenticationProvider(UserDetailsService service, PasswordEncoder encoder,UserRepository repository) {
//        this.service = service;
//        this.encoder = encoder;
//        this.repository = repository;
//    }
//
//    private final UserDetailsService service;
//    private final PasswordEncoder encoder;
//
//    private final UserRepository repository;
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//
//        String name = authentication.getName();
//        String credentials = (String) authentication.getCredentials();
//
//        AccountContext accountContext = (AccountContext) service.loadUserByUsername(name);
//        Account account = accountContext.getAccount();
//
//        if (!encoder.matches(credentials, accountContext.getAccount().getPassword()))
//        {
//            throw new BadCredentialsException("자격증명 에러");
//        }
//        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
//
//        Account byUsername = repository.findByUsername(account.getUsername());
//
////       if(!byUsername.getSecretKey().equals(secretKey)) {
////           throw new BadCredentialsException("자격증명 실패");
////       }
//
//
//        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken
//                (account, null, accountContext.getAuthorities());
//
//        return token;
//    }
//
//
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
//    }
//}
