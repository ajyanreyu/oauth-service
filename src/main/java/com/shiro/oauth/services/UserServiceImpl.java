package com.shiro.oauth.services;

import brave.Tracer;
import com.shiro.oauth.client.UserFeignClient;
import com.shiro.user.commons.entity.User;
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
    private UserFeignClient client;

    @Autowired
    private Tracer tracer;

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
        User user = client.findByUsername(username);
        log.debug("User is null");
        if (user == null) {
            log.info("logged user" + username);
            throw new UsernameNotFoundException("User '" + username + "'not found");
        }

        List<GrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .peek(authority -> log.info("Role: " + authority.getAuthority()))
                .collect(Collectors.toList());

        log.info("User logged: " + username);

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), user.getIsActive(), true,
                true, true, authorities);

    }

    @Override
    public User findByUsername(String username) {
        return client.findByUsername(username);
    }

    @Override
    public User updateLoginAttempts(Long id, User user) {
        return client.updateLoginAttempts(id, user);
    }
}
