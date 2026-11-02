package com.example.shop.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** 将 HeaderAuthInterceptor 显式注册到 /portal/**（A4 场景守卫生效）。 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new HeaderAuthInterceptor()).addPathPatterns("/portal/**");
    }
}