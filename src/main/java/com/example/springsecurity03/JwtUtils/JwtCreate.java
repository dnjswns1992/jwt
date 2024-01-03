package com.example.springsecurity03.JwtUtils;

import com.example.springsecurity03.Jpa.Account;
import com.example.springsecurity03.Jpa.AccountDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtCreate {

    private final static SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public static String createJwt(String userId,String password){
        Claims claims = Jwts.claims();

        claims.put("username",userId);
        claims.put("password",password);
        return Jwts.builder().setClaims(claims).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (60000 * 30 * 24)))
                .signWith(key).compact();
    }
}
