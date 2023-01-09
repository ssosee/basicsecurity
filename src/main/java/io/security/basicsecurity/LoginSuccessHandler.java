package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 로그인 성공 후 처리
 */
@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    // 사용자 이전 요청 정보를 세션에 저장하고 이를 꺼내오는 캐시
    private final RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        // 사용자 이전 요청 정보 조회
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if(savedRequest != null) {
            // 사용자 이전 요청 url로 redirect
            response.sendRedirect(savedRequest.getRedirectUrl());
        } else {
            response.sendRedirect("/"); // root page로 이동
        }
    }
}
