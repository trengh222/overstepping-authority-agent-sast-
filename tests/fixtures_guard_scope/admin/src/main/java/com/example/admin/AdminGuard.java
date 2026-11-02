package com.example.admin;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** admin 模块的全局拦截器：基于服务端 session 的鉴权。 */
@Component
public class AdminGuard implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String role = (String) request.getSession().getAttribute("adminRole");
        if (!"ADMIN".equals(role)) {
            response.setStatus(403);
            return false;
        }
        return true;
    }
}
