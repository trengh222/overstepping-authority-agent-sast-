package com.bac.java_a1_006;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

    private final MessageMapper messageMapper;

    public MessageController(MessageMapper messageMapper) {
        this.messageMapper = messageMapper;
    }

    @GetMapping
    public List<Map<String, Object>> inbox(@RequestParam("userId") Long userId) {
        return messageMapper.selectByUserId(userId);
    }
}
