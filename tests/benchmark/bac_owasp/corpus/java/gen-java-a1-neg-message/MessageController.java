package com.bac.gen.messages_neg;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1 负例：查询在 service 层绑定当前登录用户。 */
@RestController
@RequestMapping("/api/messages")
public class MessageController {

    @Resource
    private MessageService messagesService;

    @GetMapping("/{id}")
    public Message detail(@PathVariable("id") Long id) {
        Long uid = CurrentUser.id();
        return messagesService.getByIdAndUserId(id, uid);
    }
}
