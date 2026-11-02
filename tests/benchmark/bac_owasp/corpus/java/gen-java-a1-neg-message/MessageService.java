package com.bac.gen.messages_neg;

/** 归属过滤：id + userId 双条件。 */
public class MessageService {

    public Message getByIdAndUserId(Long id, Long userId) {
        return MessageMapper.selectByIdAndUserId(id, userId);
    }
}
