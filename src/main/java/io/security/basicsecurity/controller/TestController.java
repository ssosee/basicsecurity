package io.security.basicsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@RestController
public class TestController {

    @GetMapping("/cookie/csrf")
    public String testGET(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
        return cookie.getName()+":"+cookie.getValue();
    }

    @PostMapping("/cookie/csrf")
    public String testPost() {
        return "CookieCsrfTokenRepository";
    }

    @GetMapping("/session/csrf")
    public String getOrCreateCsrfToken(HttpServletRequest request) {
        HttpSession session = request.getSession();
        DefaultCsrfToken csrfToken = (DefaultCsrfToken) session.getAttribute("CSRF_TOKEN");

        return csrfToken.getHeaderName()+":"+csrfToken.getToken();
    }

    @PostMapping("/session/csrf")
    public String getOrCreateCsrfToken() {
        return "HttpSessionCsrfTokenRepository";
    }

}
