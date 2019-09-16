package com.shiro.oauth.services;

import com.shiro.oauth.client.UserFeignClient;
import com.shiro.user.commons.entity.User;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {

    private Logger log = LoggerFactory.getLogger(UserFeignClient.class);

    @Autowired
    private UserFeignClient userFeignClient;

    /**
     * Load user by username. Map the user of the commons library to the spring security user,
     * also map the roles to GrantedAuthority
     *
     * @param username user name
     * @return UserDetails
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        try {
            User user = userFeignClient.findByUsername(username);

            List<GrantedAuthority> authorities = user.getRoles()
                    .stream()
                    .map(role -> new SimpleGrantedAuthority(role.getName()))
                    .collect(Collectors.toList());
            log.info("logged user" + username);
            return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                    user.getIsActive(), true, true, true, authorities);
        } catch (FeignException e) {
            log.error("User '" + username + "' not found");
            throw new UsernameNotFoundException("User not found");
        }
    }

    @Override
    public User findByUsername(String username) {
        return userFeignClient.findByUsername(username);
    }

    @Override
    public User updateLoginAttempts(Long id, User user) {
        return userFeignClient.updateLoginAttempts(id, user);
    }
}
