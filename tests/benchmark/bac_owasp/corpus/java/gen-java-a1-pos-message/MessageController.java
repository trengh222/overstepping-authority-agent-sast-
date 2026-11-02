package com.bac.gen.messages_pos;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1：路径参数 id 直接查库并返回，没有任何归属校验。 */
@RestController
@RequestMapping("/api/messages")
public class MessageController {

    @Resource
    private MessageService messagesService;

    @GetMapping("/{id}")
    public Message detail(@PathVariable("id") Long id) {
        return messagesService.getById(id);
    }
}
