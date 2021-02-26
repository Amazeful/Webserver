/*
 * Copyright (c) 2021. Amazeful. All rights reserved!
 */

package com.amazefulbot.WebServer.config;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.*;
import java.util.Date;

@Service
public class JWTProvider {
    @Value("${app.auth.expiration}")
    private int expiration;

    @Value("${app.auth.secret}")
    private String secret;

    @Value("${app.auth.header}")
    private String header;

    public String createToken() {
        Date now = new Date();
        UserPrincipal userPrincipal = (UserPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .setSubject(Integer.toString(userPrincipal.getUser().getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public int getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();

        return Integer.parseInt(claims.getSubject());
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(authToken);
            return true;
        } catch (Exception ex) {
            return false;
        }

    }

}
