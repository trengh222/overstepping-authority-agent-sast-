package com.example.app.web;

import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 注册可达正样本：包 com.example.app.web 被 com.example.app 扫描根覆盖 → 已注册。 */
@RestController
@RequestMapping("/api/order")
public class ScannedController {

    @Autowired
    private OrderService orderService;

    @GetMapping("/{id}")
    public Object getOrder(@PathVariable("id") Long id) {
        return orderService.findById(id);
    }
}
