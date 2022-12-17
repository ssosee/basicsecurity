package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
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
    private final UserDetailsService userDetailsService;

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

        //스프링 시큐리티는 post 방식으로 logout 지원
        http
                .logout() // 로그아웃 처리
                .logoutUrl("/logout") // 로그아웃 처리 URL
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동 URL
                .deleteCookies("JSESSIONID" , "remember-me") // 로그아웃 후 쿠키 삭제
                .addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃 성공 후 핸들러
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me");

        http
                .rememberMe()
                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600) // default 는 14일
                .alwaysRemember(true) // remember-me 기능이 활성화되지 않아도 항상 실행 유무
                .userDetailsService(userDetailsService);

        http
                .sessionManagement() // 세션 관리 기능이 작동
                .sessionFixation().changeSessionId() // 따로 작성하지 않아도 기본값
                // changeSessionId(): 세션 아이디 변경, none(): 세션 고정 보호 미설정, migrateSession(): 서블릿 3.1 이하에서 changeSessionId() 작동하도록, newSession(): 새로운 세션 생성
                .invalidSessionUrl("/invalid") // 세션이 유효하지 않을 경우 이동할 페이지
                .maximumSessions(1) // 최대 허용 가능 세션 수(-1: 무제한 로그인 세션 허용)
                .expiredUrl("/expired") // 세션이 만료될 경우 이동할 페이지
                .maxSessionsPreventsLogin(false)// 동시 로그인 차단함 (false: 기존 세션 만료(default)
        ;
    }

    /**
     * 세션 정책 설정
     */
    private void sessionManagement(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                ;
        /**
         * SessionCreationPolicy.IF_REQUIRED    : 스프링 시큐리티가 필요시 세션 생성 (default)
         * SessionCreationPolicy.ALWAYS         : 스프링 시큐리티가 항상 세션 생성
         * SessionCreationPolicy.NEVER          : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
         * SessionCreationPolicy.STATELESS      : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음 (JWT)
         */
    }
}
