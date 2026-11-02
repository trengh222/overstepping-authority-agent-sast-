package com.example.shop.config;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** 负样本守卫：基于服务端 session 的鉴权，不依赖客户端可控输入。 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String role = (String) request.getSession().getAttribute("role");
        if (!"ADMIN".equals(role)) {
            response.setStatus(403);
            return false;
        }
        return true;
    }
}