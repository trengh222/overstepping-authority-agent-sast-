package com.bac.gen.tickets_neg;

/** 归属过滤：id + userId 双条件。 */
public class TicketService {

    public Ticket getByIdAndUserId(Long id, Long userId) {
        return TicketMapper.selectByIdAndUserId(id, userId);
    }
}
