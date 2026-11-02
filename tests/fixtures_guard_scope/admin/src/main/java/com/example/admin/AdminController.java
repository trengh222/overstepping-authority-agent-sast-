package com.example.admin;

import com.example.shop.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** D1 负样本：admin 模块的特权端点，由本模块 AdminGuard 保护 → 不应产出 A3。 */
@RestController
@RequestMapping("/manage")
public class AdminController {

    @Autowired
    private UserService userService;

    @DeleteMapping("/user/{id}")
    public void deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
    }
}
