package com.example.shop.admin;

import com.example.shop.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/** A2 正样本：特权删除，仅 @PreAuthorize("isAuthenticated()") —— 只认证、不授权。 */
@RestController
@RequestMapping("/manage")
public class AdminControllerWeak {

    @Autowired
    private UserService userService;

    @DeleteMapping("/user/{id}")
    @PreAuthorize("isAuthenticated()")
    public void deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
    }
}