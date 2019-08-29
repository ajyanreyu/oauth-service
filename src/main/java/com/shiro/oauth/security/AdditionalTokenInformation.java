package com.shiro.oauth.security;

import com.shiro.oauth.services.UserService;
import com.shiro.user.commons.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * This class implements an example of how additional information is added to the token
 */
@Component
public class AdditionalTokenInformation implements TokenEnhancer {
    @Autowired
    private UserService userService;

    /**
     * Add additional content to the token
     *
     * @param oAuth2AccessToken
     * @param oAuth2Authentication
     * @return OAuth2AccessToken
     * @author Albano Yanes <ajyanreyu@gmail.com>
     */
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        Map<String, Object> info = new HashMap<String, Object>();
        User user = userService.findByUsername(oAuth2Authentication.getName());
        info.put("name", user.getName());
        info.put("last_name", user.getLastName());
        info.put("email", user.getEmail());

        ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(info);

        return oAuth2AccessToken;
    }
}
