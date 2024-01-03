package com.example.springsecurity03.Handler;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
@Component
public class CustomAuthenticationHandler extends SimpleUrlAuthenticationSuccessHandler {


    private RedirectStrategy strategy = new DefaultRedirectStrategy();
    private RequestCache requestCache = new HttpSessionRequestCache();
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        setDefaultTargetUrl("/");
        if(savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();
            strategy.sendRedirect(request,response,redirectUrl);
        }else {
            strategy.sendRedirect(request,response,getDefaultTargetUrl());
        }

    }
}
