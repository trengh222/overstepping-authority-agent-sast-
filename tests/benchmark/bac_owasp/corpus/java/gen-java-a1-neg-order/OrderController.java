package com.bac.gen.orders_neg;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1 负例：查询在 service 层绑定当前登录用户。 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @Resource
    private OrderService ordersService;

    @GetMapping("/{id}")
    public Order detail(@PathVariable("id") Long id) {
        Long uid = CurrentUser.id();
        return ordersService.getByIdAndUserId(id, uid);
    }
}
