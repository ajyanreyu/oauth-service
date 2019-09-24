package com.shiro.oauth.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private Logger log = LoggerFactory.getLogger(SpringSecurityConfig.class);

    @Autowired
    @Qualifier("userServiceImpl")
    private UserDetailsService userService;

    @Autowired
    private AuthenticationEventPublisher authenticationEventPublisher;

    /**
     * Register the user services in the authentication manager
     *
     * @param auth AuthenticationManagerBuilder
     * @throws Exception
     */
    @Override
    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        log.debug("Configure auth manager");
        auth.userDetailsService(this.userService).passwordEncoder(passwordEncoder())
                .and()
                .authenticationEventPublisher(authenticationEventPublisher);

    }

    /**
     * Encrypt passwords to BCrypt
     *
     * @return BCryptPasswordEncoder
     * @author Albano yanes <ajyanreyu@gmail.com>
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        log.debug("Encrypt passwords to BCrypt");
        return new BCryptPasswordEncoder();
    }


    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();

    }
}
