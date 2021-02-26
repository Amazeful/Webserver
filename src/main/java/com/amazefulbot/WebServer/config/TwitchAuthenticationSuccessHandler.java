/*
 * Copyright (c) 2021. Amazeful. All rights reserved!
 */

package com.amazefulbot.WebServer.config;

import com.amazefulbot.WebServer.utils.CookieUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Component
public class TwitchAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler implements AuthenticationSuccessHandler  {

    private JWTProvider jwtProvider;

    @Value("${app.auth.header}")
    private String header;

    @Value("${app.auth.prefix}")
    private String prefix;



    private TwitchOauthRequestRepository twitchOauthRequestRepository;


    @Autowired
    TwitchAuthenticationSuccessHandler(JWTProvider jwtProvider, AppProperties appProperties,
                                       TwitchOauthRequestRepository twitchOauthRequestRepository) {
        this.jwtProvider = jwtProvider;
        this.twitchOauthRequestRepository = twitchOauthRequestRepository;
    }



    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtil.getCookie(request, TwitchOauthRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        return targetUrl;
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        twitchOauthRequestRepository.removeAuthorizationRequestCookies(request, response);
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(httpServletRequest, httpServletResponse, authentication);

        if (httpServletResponse.isCommitted()) {
            logger.debug("Response has already been committed");
            return;
        }
        String token = jwtProvider.createToken();
        httpServletResponse.setHeader(header, prefix + token);
        clearAuthenticationAttributes(httpServletRequest, httpServletResponse);
        getRedirectStrategy().sendRedirect(httpServletRequest, httpServletResponse, targetUrl);
    }
}