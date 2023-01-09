package io.security.basicsecurity;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}123").roles("USER");
        auth.inMemoryAuthentication().withUser("manager").password("{noop}123").roles("MANAGER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}123").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/manager").hasRole("MANAGER")
                .antMatchers("/admin-manager").access("hasRole('ADMIN') or hasRole('MANAGER')")
                .anyRequest().authenticated();

        http
                .formLogin()
                .defaultSuccessUrl("/user");
    }
}
