package com.bac.gen.messages_pos;

/** 无所有权过滤：按主键直接取。 */
public class MessageService {

    public Message getById(Long id) {
        return MessageMapper.selectById(id);
    }
}
