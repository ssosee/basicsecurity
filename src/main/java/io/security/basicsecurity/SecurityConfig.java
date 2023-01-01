package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static javax.management.Query.and;

/**
 * <h1>현재 Deprecated 됨</h1>
 * <a href="https://velog.io/@pjh612/Deprecated%EB%90%9C-WebSecurityConfigurerAdapter-%EC%96%B4%EB%96%BB%EA%B2%8C-%EB%8C%80%EC%B2%98%ED%95%98%EC%A7%80">
 *     참고</a>
 */
//@Configuration
//@EnableWebSecurity // 웹 보안 활성화
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;
    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}123").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}123").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}123").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //basicConfigure(http);
        //formConfigure(http);
        //logout(http);
        //rememberMe(http);
        //authorizeUrl(http);
        //exception(http);
        //csrf(http);

//        http
//                .authorizeRequests() // 요청에 대한 보안 검사
//                //.antMatchers("/loginPage").permitAll() // 어떤 요청도 허용
//                .anyRequest().authenticated(); // 어떤 요청에도 인증을 받음
//
//        http
//                .formLogin()
//                //.loginPage("/loginPage") //사용자 정의 로그인 페이지
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                //.successHandler(loginSuccessHandler)
//                //.failureHandler(loginFailureHandler)
//                .permitAll();
//
//        //스프링 시큐리티는 post 방식으로 logout 지원
//        http
//                .logout() // 로그아웃 처리
//                .logoutUrl("/logout") // 로그아웃 처리 URL
//                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동 URL
//                .deleteCookies("JSESSIONID" , "remember-me") // 로그아웃 후 쿠키 삭제
//                .addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃 성공 후 핸들러
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("remember-me");
//
//        http
//                .rememberMe()
//                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
//                .tokenValiditySeconds(3600) // default 는 14일
//                .alwaysRemember(true) // remember-me 기능이 활성화되지 않아도 항상 실행 유무
//                .userDetailsService(userDetailsService);
//
//        http
//                .sessionManagement() // 세션 관리 기능이 작동
//                .sessionFixation().changeSessionId() // 따로 작성하지 않아도 기본값
//                // changeSessionId(): 세션 아이디 변경, none(): 세션 고정 보호 미설정, migrateSession(): 서블릿 3.1 이하에서 changeSessionId() 작동하도록, newSession(): 새로운 세션 생성
//                .invalidSessionUrl("/invalid") // 세션이 유효하지 않을 경우 이동할 페이지
//                .maximumSessions(1) // 최대 허용 가능 세션 수(-1: 무제한 로그인 세션 허용)
//                .expiredUrl("/expired") // 세션이 만료될 경우 이동할 페이지
//                .maxSessionsPreventsLogin(false)// 동시 로그인 차단함 (false: 기존 세션 만료(default)
//        ;
    }

    private void basicConfigure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin();
    }

    private void formConfigure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        http
                .formLogin()
                //.loginPage("/loginPage") // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/home", true) // 로그인 성공 후 이동 페이지(default false)
                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") // 아이디 파라미터명 설정
                .passwordParameter("passwd") // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc") // 로그인 from action url
                .successHandler(loginSuccessHandler) // 로그인 성공 후 핸들러
                .failureHandler(loginFailureHandler) // 로그인 실패 후 핸들러
                .permitAll();
    }

    private void logout(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/home2").permitAll()
                .anyRequest().authenticated();

        http
                .formLogin();

        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .deleteCookies("JSESSIONID", "remember-me")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/home2");
                    }
                });
    }

    private void rememberMe(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                        .anyRequest().authenticated();
        http
                .formLogin();

        http
                .rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .alwaysRemember(false)
                .userDetailsService(userDetailsService);
    }

    /**
     * 세션 정책 설정
     */
    private void sessionManagement(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();

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

    /**
     * 세션 고정 보호
     */
    private void sessionFixedProtection(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .anyRequest().authenticated();

        http
                .sessionManagement()
                .sessionFixation().changeSessionId();
        // changeSessionId(): 세션 아이디 변경,
        // none(): 세션 고정 보호 미설정,
        // migrateSession(): 서블릿 3.1 이하에서 changeSessionId() 작동하도록,
        // newSession(): 새로운 세션 생성
    }

    /**
     * 동시 세션 제어 (sessionManagement())
     */
    private void concurrentSessionControl(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .anyRequest().authenticated();

        http
                .sessionManagement()
                //.invalidSessionUrl("/invalid") // 세션이 유효하지 않을 때 이동할 페이지
                .maximumSessions(1) // 최대 허용 가능 세션 수
                .maxSessionsPreventsLogin(true) // 동시로그인 차단, false: 기존 세션 만료
                //.expiredUrl("/expired") // 세션이 만료된 경우 이동 할 페이지
         ;
    }

    /**
     * 권한 설정
     * URL 방식
     *
     * 설정 시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 한다.
     */
    private void authorizeUrl(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http
                .formLogin();

//        http
//                .antMatcher("/shop/**")
//                .authorizeRequests()
//                .antMatchers("/shop/login", "/shop/users/**").permitAll()
//                .antMatchers("/shop/mapage").hasRole("USER")
//                .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
//                .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//                .anyRequest().authenticated();
    }

    private void exception(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/loginPage").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        /**
                         * 사용자의 이전 요청 정보를 세션에 저장하고, 이를 꺼내오는 캐시 메커  니즘
                         */
                        RequestCache requestCache = new HttpSessionRequestCache();
                        // 사용자가 요청했던 request 파라미터 값들, 그 당시의 헤더값들 등이 저장
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        // 사용자가 원래 가고싶은 URL로 이동
                        response.sendRedirect(savedRequest.getRedirectUrl());
                    }
                });

        http
                .exceptionHandling() //인증, 인가 예외 처리
//                .authenticationEntryPoint(new AuthenticationEntryPoint() { //인증실패 시 처리
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                         response.sendRedirect("/loginPage"); //사용자가 만든 로그인 페이지 이동
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() { //인가실패 시 처리
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });
    }

    /**
     * Cross Site Request Forgery
     */
    private void csrf(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().permitAll();

        http
                .formLogin();

//        http
//                .csrf().disable();
    }
}
