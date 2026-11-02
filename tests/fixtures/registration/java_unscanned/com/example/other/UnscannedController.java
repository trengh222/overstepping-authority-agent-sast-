package com.example.other;

import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 注册可达负样本：包 com.example.other 不在任何组件扫描根内，且未被 @Import。 */
@RestController
@RequestMapping("/api/order")
public class UnscannedController {

    @Autowired
    private OrderService orderService;

    @GetMapping("/{id}")
    public Object getOrder(@PathVariable("id") Long id) {
        return orderService.findById(id);
    }
}
