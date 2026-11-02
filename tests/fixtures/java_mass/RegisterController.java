package com.example.shop.api;

import com.example.shop.bean.User;
import com.example.shop.repo.UserRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/** A4 正/负样本（规则 C）：admin 由客户端参数直接进 setter 后入库（自封管理员提权）。 */
@RestController
@RequestMapping("/api")
public class RegisterController {

    private final UserRepository userRepository;

    public RegisterController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /** 正样本：admin 形参直接 setter，随后 save。 */
    @PostMapping("/register")
    @PreAuthorize("isAnonymous()")
    public void register(@RequestParam("admin") boolean admin) {
        User user = new User();
        user.setAdmin(admin);
        userRepository.save(user);
    }

    /** 负样本：admin 服务端硬编码 false。 */
    @PostMapping("/register_safe")
    @PreAuthorize("isAnonymous()")
    public void registerSafe(@RequestParam("name") String name) {
        User user = new User();
        user.setUsername(name);
        user.setAdmin(false);
        userRepository.save(user);
    }
}