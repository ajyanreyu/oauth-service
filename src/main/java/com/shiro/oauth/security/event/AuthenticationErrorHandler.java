package com.shiro.oauth.security.event;

import com.shiro.oauth.services.UserService;
import com.shiro.user.commons.entity.User;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationErrorHandler implements AuthenticationEventPublisher {

    private Logger log = LoggerFactory.getLogger(AuthenticationErrorHandler.class);

    @Autowired
    private UserService userService;

    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
        UserDetails user = (UserDetails) authentication.getPrincipal();
        log.info("Sucess login " + user.getUsername());
        User currentUser = userService.findByUsername(authentication.getName());
        if (currentUser.getLoginAttempts() != null && currentUser.getLoginAttempts() > 0) {
            currentUser.setLoginAttempts(0);
            userService.updateLoginAttempts(currentUser.getId(), currentUser);
        }

    }

    @Override
    public void publishAuthenticationFailure(AuthenticationException e, Authentication authentication) {
        log.error("Login error " + e.getMessage());

        try {
            User user = userService.findByUsername(authentication.getName());
            if (user.getLoginAttempts() == null) {
                user.setLoginAttempts(0);
            }
            user.setLoginAttempts(user.getLoginAttempts() + 1);
            log.info("Login attempts: " + user.getLoginAttempts());
            if (user.getLoginAttempts() >= 3) {
                log.info(String.format("User %s disabled by maximum number of attempts", user.getUsername()));
                user.setIsActive(false);
            }
            userService.updateLoginAttempts(user.getId(), user);
        } catch (FeignException ex) {
            log.error(String.format("username %s is not found", authentication.getName()));
            log.error(ex.getMessage());
        }

    }
}
