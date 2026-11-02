package com.bac.gen.tickets_pos;

/** 无所有权过滤：按主键直接取。 */
public class TicketService {

    public Ticket getById(Long id) {
        return TicketMapper.selectById(id);
    }
}
