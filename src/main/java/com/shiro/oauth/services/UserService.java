package com.shiro.oauth.services;

import com.shiro.user.commons.entity.User;

public interface UserService {

    /**
     * Find user by username
     * @param username
     * @return User
     * @author Albano Yanes <ajyanreyu@gmail.com>
     */
    public User findByUsername(String username);
}
