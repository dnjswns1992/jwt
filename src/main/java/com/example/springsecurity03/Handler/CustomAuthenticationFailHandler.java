package com.example.springsecurity03.Handler;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationFailHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = "아이디 또는 비밀번호가 맞지 않습니다.";

        if(exception instanceof BadCredentialsException){
            errorMessage = "아이디 또는 비밀번호가 맞지 않습니다";
        }
        setDefaultFailureUrl("/login");

        super.onAuthenticationFailure(request,response,exception);
    }
}
