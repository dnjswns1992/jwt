package com.example.springsecurity03.JwtUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletResponse;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtUtil {

    private final static SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public static String createJwt(String userId,String password){
        Claims claims = Jwts.claims();

        claims.put("username",userId);
        claims.put("password",password);
        return Jwts.builder().setClaims(claims).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (60000 * 30 * 24)))
                .signWith(key).compact();
    }
    public static Claims getUsername(String token , HttpServletResponse response){
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

}
