package com.example.web;

import com.example.shop.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** D1 正样本：web 模块无拦截器；admin 模块的全局拦截器不得让它「被覆盖」。 */
@RestController
@RequestMapping("/manage")
public class WebController {

    @Autowired
    private UserService userService;

    @DeleteMapping("/user/{id}")
    public void deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
    }
}
