package com.example.springsecurity03.Filter;

import com.example.springsecurity03.Jpa.Account;
import com.example.springsecurity03.JwtUtils.JwtUtil;
import com.example.springsecurity03.Repository.UserRepository;
import com.example.springsecurity03.Service.AccountContext;
import com.example.springsecurity03.Service.UserService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Optional;

@RequiredArgsConstructor
@Slf4j
public class JwtCheckFilter extends OncePerRequestFilter{

    private final UserRepository repository;



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        String authorization = null;

       authorization =  request.getHeader("Authorization");



        if(!request.getRequestURI().startsWith("/user/") && !request.getRequestURI().startsWith("/admin")){
           filterChain.doFilter(request,response);
           return;
       }

       if(authorization == null || !authorization.startsWith("Bearer ")){
           response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
           return;
       }

       try {
           String token = authorization.split(" ")[1];

           Claims username = JwtUtil.getUsername(token, response);

           if(username != null) {
               String resultUserName = username.get("username", String.class);
               Account byUsername = repository.findByUsername(resultUserName);

               if(request.getRequestURI().startsWith("/admin") && byUsername.getRole().equals("ROLE_USER")) {
                   response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                   return;
               }

               if(byUsername == null) {
                   response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                   return;
               }


               AccountContext context = new AccountContext(byUsername);


               UsernamePasswordAuthenticationToken userToken =
                       new UsernamePasswordAuthenticationToken(context,context.getPassword(),context.getAuthorities());

               SecurityContextHolder.getContext().setAuthentication(userToken);

               filterChain.doFilter(request,response);
           }else {
               response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
           }
       }catch (Exception e) {
           log.info(e.getMessage());

            if(e instanceof io.jsonwebtoken.security.SignatureException) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
       }

    }
}
