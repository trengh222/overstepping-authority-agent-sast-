package com.example.shop.admin;

import com.example.shop.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/** A4 正样本：特权操作，仅被客户端可控的 HeaderAuthInterceptor 覆盖（注册到 /portal/**）。 */
@RestController
@RequestMapping("/portal")
public class AdminControllerClient {

    @Autowired
    private UserService userService;

    @PostMapping("/user")
    public void createUser(@RequestBody Map<String, Object> body) {
        userService.saveUser(body);
    }
}