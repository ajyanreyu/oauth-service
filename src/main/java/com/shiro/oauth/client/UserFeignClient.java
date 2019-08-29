package com.shiro.oauth.client;

import com.shiro.user.commons.entity.User;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * we define the service we are going to consume, in this case user service
 */
@FeignClient(name = "user-service")
public interface UserFeignClient {

    @GetMapping("/user/search/find-username")
    public User findByUsername(@RequestParam String username);


}
