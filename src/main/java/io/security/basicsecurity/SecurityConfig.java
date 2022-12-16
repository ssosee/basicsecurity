package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <h1>현재 Deprecated 됨</h1>
 * <a href="https://velog.io/@pjh612/Deprecated%EB%90%9C-WebSecurityConfigurerAdapter-%EC%96%B4%EB%96%BB%EA%B2%8C-%EB%8C%80%EC%B2%98%ED%95%98%EC%A7%80">
 *     참고</a>
 */
@Configuration
@EnableWebSecurity // 웹 보안 활성화
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;


    /**
     * <pre>
     *     http.formLogin()
     *             .loginPage("/login.html") // 사용자 정의 로그인 페이지
     *             .defaultSuccessUrl("/home") // 로그인 성공 후 이동 페이지
     *             .failureUrl("/login.html?error=true") // 로그인 실패 후 이동 페이지
     *             .usernameParameter("username") // 아이디 파라미터명 설정
     *             .passwordParameter("password") // 패스워스 파라미터명 설정
     *             .loginProcessingUrl("/login") // 로그인 Form Action Url
     *             .successHandler(loginSuccessHandler) // 로그인 성공 후 핸들러
     *             .failureHandler(loginFailureHandler) // 로그인 실패 후 핸들러
     * </pre>
     */

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests() // 요청에 대한 보안 검사
                //.antMatchers("/loginPage").permitAll() // 어떤 요청도 허용
                .anyRequest().authenticated(); // 어떤 요청에도 인증을 받음

        http
                .formLogin()
                //.loginPage("/loginPage") //사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                //.successHandler(loginSuccessHandler)
                //.failureHandler(loginFailureHandler)
                .permitAll();
    }
}
