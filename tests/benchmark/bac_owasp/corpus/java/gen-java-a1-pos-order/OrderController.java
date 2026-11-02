package com.bac.gen.orders_pos;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1：路径参数 id 直接查库并返回，没有任何归属校验。 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @Resource
    private OrderService ordersService;

    @GetMapping("/{id}")
    public Order detail(@PathVariable("id") Long id) {
        return ordersService.getById(id);
    }
}
