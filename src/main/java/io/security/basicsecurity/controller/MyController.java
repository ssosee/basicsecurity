package io.security.basicsecurity.controller;

import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@Controller
public class MyController {

    String csrf = "";
    @ResponseBody
    @GetMapping("/")
    public String root(@CookieValue(value = "XSRF-TOKEN") String _csrf) {
        return "csrf="+_csrf;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
