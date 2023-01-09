package io.security.basicsecurity;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;


@Controller
public class MyController {
    @ResponseBody
    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @ResponseBody
    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @ResponseBody
    @GetMapping("/admin-manager")
    public String adminManager() {
        return "admin-manager";
    }

    @ResponseBody
    @GetMapping("/denied")
    public String denied(@RequestParam(value = "exception", required = false) String exception) {
        return exception;
    }

    @GetMapping("/login")
    public String login(@RequestParam(value = "exception", required = false) String exception,
                        Model model) {

        model.addAttribute("exception", exception);

        return "login";
    }

    @ResponseBody
    @GetMapping("/hello")
    public String hello() {
        return "hello! 사용자 이전 요청 페이지";
    }

    @ResponseBody
    @GetMapping("/")
    public String root() {
        return "root page";
    }
}
