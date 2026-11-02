package com.example.shop.admin;

import com.example.shop.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/** A2 负样本：特权删除，@PreAuthorize("hasRole('ROLE_ADMIN')") —— 授权足够。 */
@RestController
@RequestMapping("/manage")
public class AdminControllerStrong {

    @Autowired
    private UserService userService;

    @DeleteMapping("/user/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public void deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
    }
}