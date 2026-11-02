package com.example.shop;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** D7 样本：无注解的 userId 不在路径模板中 → 应为 QUERY（不是 PATH）。 */
@RestController
@RequestMapping("/api/user")
public class ImplicitQueryController {

    @Autowired
    private OrderService orderService;

    @GetMapping("/userInfo")
    public Object userInfo(Long userId) {
        return orderService.findById(userId);
    }
}
