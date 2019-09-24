package com.shiro.oauth.services;

import com.shiro.user.commons.entity.User;

public interface UserService{

    /**
     * Find user by username
     * @param username
     * @return User
     * @author Albano Yanes <ajyanreyu@gmail.com>
     */
    public User findByUsername(String username);

    /**
     * Update user login attempts
     * @param id user id
     * @param user user data
     * @return User
     */
    public User updateLoginAttempts(Long id, User user);
}
