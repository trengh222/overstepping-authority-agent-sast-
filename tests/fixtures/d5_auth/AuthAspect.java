package com.example.shop;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

/** D5 样本：@Before("@annotation(RequireLogin)") 切面校验 header token + Redis。 */
@Aspect
@Component
public class AuthAspect {

    @Before("@annotation(com.example.shop.RequireLogin)")
    public void checkLogin(JoinPoint point) {
        String token = request.getHeader("token");
        if (token == null || !redis.hasKey("easylive:token:web:" + token)) {
            throw new RuntimeException("need login");
        }
    }
}
