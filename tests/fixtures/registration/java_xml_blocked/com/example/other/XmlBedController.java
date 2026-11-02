package com.example.other;

import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 注册可达安全闸样本：包未被扫描，但仓库有 XML Bean 配置 → 不作确定性关闭。 */
@RestController
@RequestMapping("/api/order")
public class XmlBedController {

    @Autowired
    private OrderService orderService;

    @GetMapping("/{id}")
    public Object getOrder(@PathVariable("id") Long id) {
        return orderService.findById(id);
    }
}
