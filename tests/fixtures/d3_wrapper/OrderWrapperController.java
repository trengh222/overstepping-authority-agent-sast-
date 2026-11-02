package com.example.shop;

import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

/** D3 样本：控制器包装方法（getSuccessResponseVO / readFile）不得作为数据 sink。 */
@RestController
@RequestMapping("/api/order")
public class OrderWrapperController {

    @Autowired
    private OrderService orderService;

    // 真 sink 是内层 orderService.findById；外层 getSuccessResponseVO 只是响应包装
    @GetMapping("/{id}")
    public Object getOrder(@PathVariable("id") Long id) {
        return getSuccessResponseVO(orderService.findById(id));
    }

    // readFile 是控制器本地 IO 包装，不是授权数据 sink（无其他 DAO 调用 → 不应产出）
    @GetMapping("/file/{id}")
    public void getFile(@PathVariable("id") Long id, HttpServletResponse response) {
        readFile(response, id + ".mp4");
    }

    private Object getSuccessResponseVO(Object data) {
        return data;
    }

    private void readFile(HttpServletResponse response, String path) {
    }
}
