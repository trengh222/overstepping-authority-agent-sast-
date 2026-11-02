package com.bac.gen.tickets_neg;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1 负例：查询在 service 层绑定当前登录用户。 */
@RestController
@RequestMapping("/api/tickets")
public class TicketController {

    @Resource
    private TicketService ticketsService;

    @GetMapping("/{id}")
    public Ticket detail(@PathVariable("id") Long id) {
        Long uid = CurrentUser.id();
        return ticketsService.getByIdAndUserId(id, uid);
    }
}
