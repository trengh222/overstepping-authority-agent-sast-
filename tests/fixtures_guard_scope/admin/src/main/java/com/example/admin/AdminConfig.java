package com.example.admin;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** admin 模块把 AdminGuard 注册到 /**：只应覆盖 admin 模块自身。 */
@Configuration
public class AdminConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AdminGuard()).addPathPatterns("/**");
    }
}
