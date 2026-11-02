package com.example.shop.admin;

import com.example.shop.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/** 负样本：特权操作，被 session 鉴权的 AuthInterceptor 覆盖（/admin/safe/**）。 */
@RestController
@RequestMapping("/admin/safe")
public class AdminControllerSafe {

    @Autowired
    private UserService userService;

    @DeleteMapping("/user/{id}")
    public void deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
    }
}