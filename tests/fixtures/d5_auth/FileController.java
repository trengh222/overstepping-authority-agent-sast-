package com.example.shop;

import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** D5 样本：自定义 AOP 鉴权注解（checkLogin 参数 / 切面注解）识别。 */
@RestController
@RequestMapping("/file")
public class FileController {

    @Autowired
    private OrderService orderService;

    @GlobalInterceptor(checkLogin = true)
    @GetMapping("/uploadVideo")
    public Object upload(@RequestParam("fileId") Long fileId) {
        return orderService.findById(fileId);
    }

    @GlobalInterceptor(checkLogin = false)
    @GetMapping("/public")
    public Object publicInfo(@RequestParam("id") Long id) {
        return orderService.findById(id);
    }

    @RequireLogin
    @GetMapping("/custom/{id}")
    public Object custom(@PathVariable("id") Long id) {
        return orderService.findById(id);
    }
}
