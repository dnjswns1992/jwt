package com.example.springsecurity03.Handler;

import com.example.springsecurity03.Jpa.Account;
import com.example.springsecurity03.Jpa.AccountDto;
import com.example.springsecurity03.JwtUtils.JwtCreate;
import com.example.springsecurity03.Repository.UserRepository;
import com.example.springsecurity03.Service.AccountContext;
import com.example.springsecurity03.Service.CustomUserDetailsService;
import com.example.springsecurity03.Service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

@Component
@Slf4j
public class UserCheckFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager manager;
    private final  UserRepository repository;

    //시큐리티 버전업이 되어 Manager클래스는 직접 넣어야한다.
    //DB 클래스도 직접넣어야한다.
    public UserCheckFilter(AuthenticationManager manager, UserRepository repository) {
        super(manager);
        this.manager = manager;
        this.repository = repository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        ObjectMapper mapper = new ObjectMapper();


        try {
            AccountDto accountDto = mapper.readValue(request.getInputStream(), AccountDto.class);
            UsernamePasswordAuthenticationToken token
                    = new UsernamePasswordAuthenticationToken(accountDto.getUsername(),accountDto.getPassword()
            , List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));

           return manager.authenticate(token);
        } catch (IOException e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        log.info("클래스 확인 = {}",authResult.getPrincipal());
        UserDetails principal = (UserDetails) authResult.getPrincipal();
        String jwtToken = JwtCreate.createJwt(principal.getPassword(),principal.getPassword());
        Account byUsername = repository.findByUsername(principal.getUsername());

        if(byUsername != null) {
            response.addHeader("Authorization","Bearer "+jwtToken);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

        }

    }
}
