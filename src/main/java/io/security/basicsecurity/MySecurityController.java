package io.security.basicsecurity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

import static org.springframework.security.core.context.SecurityContextHolder.MODE_GLOBAL;

@Slf4j
@RestController
public class MySecurityController {

    @GetMapping("/")
    public String index(HttpSession session) {
        SecurityContext securityContext = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
        Authentication authentication2 = securityContext.getAuthentication();

        log.info("authentication1={}", authentication1);
        log.info("authentication2={}", authentication2);
        log.info("authentication1 == authentication2 ? = {}", authentication1 == authentication2);

        return "home";
    }

    @GetMapping("/thread")
    public String thread() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("authentication={}", authentication);

        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        /**
                         * ThreadLocal이 Main Thread와 다름
                         * SecurityContextHolder의 기본 전략인 MODE_THREADLOCAL으로 설정되었기 때문
                         */
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                        log.info("Thread authentication={}", authentication);
                    }
                }
        ).start();

        return "thread";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/home2")
    public String home2() {
        return "home2";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }

    @PostMapping("/")
    public String root() {
        return "root";
    }
}
