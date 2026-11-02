package com.bac.gen.tickets_pos;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1：路径参数 id 直接查库并返回，没有任何归属校验。 */
@RestController
@RequestMapping("/api/tickets")
public class TicketController {

    @Resource
    private TicketService ticketsService;

    @GetMapping("/{id}")
    public Ticket detail(@PathVariable("id") Long id) {
        return ticketsService.getById(id);
    }
}
