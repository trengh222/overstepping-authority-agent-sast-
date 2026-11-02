package com.example.shop;

import com.example.shop.service.OrderService;
import java.security.Principal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/order")
public class OrderController {

    @Autowired
    private OrderService orderService;

    // 正样本：跨过程进入 Service → Repository，无归属
    @GetMapping("/{id}")
    public Object getOrder(@PathVariable Long id) {
        return orderService.findById(id);
    }

    // 正样本：单跳别名 + 跨过程（oid = id 后再传入）
    @GetMapping("/alias/{id}")
    public Object getAlias(@PathVariable Long id) {
        Long oid = id;
        return orderService.findById(oid);
    }

    // 负样本：Service 层方法名含 User 归属 → 应被过滤
    @GetMapping("/mine/{id}")
    public Object getMine(@PathVariable Long id, Principal principal) {
        return orderService.findByUserIdAndId(principal.getName(), id);
    }
}