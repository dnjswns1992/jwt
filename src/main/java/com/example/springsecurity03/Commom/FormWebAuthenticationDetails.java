package com.example.springsecurity03.Commom;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
@Getter
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;
    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("SecretKey");
    }
}
