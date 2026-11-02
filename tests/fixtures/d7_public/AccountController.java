package com.example.shop;

import com.example.shop.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** D7 样本：登录/登出等公开认证流程，即使被识别为特权写也不报 A3。 */
@RestController
@RequestMapping("/account")
public class AccountController {

    @Autowired
    private UserService userService;

    @DeleteMapping("/login")
    public void login() {
        userService.deleteUser(1L);
    }
}
