package com.example.shop.config;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** A4 正样本：鉴权决策依赖客户端可控的请求头 X-Role，可被伪造绕过。 */
@Component
public class HeaderAuthInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String role = request.getHeader("X-Role");
        if (!"ADMIN".equals(role)) {
            response.setStatus(403);
            return false;
        }
        return true;
    }
}