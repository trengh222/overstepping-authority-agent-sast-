package com.example.shop.admin;

import com.example.shop.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/** A3 正样本：特权操作（删除用户），全链路无任何鉴权。 */
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