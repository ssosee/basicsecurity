package io.security.basicsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.LazyCsrfTokenRepository;

@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .anyRequest().permitAll();

        http
                .formLogin();

        http
                .csrf().csrfTokenRepository(cookieCsrfTokenRepository());

//        http
//                .csrf().csrfTokenRepository(httpSessionCsrfTokenRepository());
    }

    @Bean
    public HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository() {
        HttpSessionCsrfTokenRepository csrfRepository = new HttpSessionCsrfTokenRepository();
        // 기본값이 "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN" 입니다.
        // 기본값이 너무 길어서 따로 설정하는것이 좋습니다.
        csrfRepository.setSessionAttributeName("CSRF_TOKEN");
        return csrfRepository;
    }

    @Bean
    public CookieCsrfTokenRepository cookieCsrfTokenRepository() {
        return new CookieCsrfTokenRepository();
    }
}
