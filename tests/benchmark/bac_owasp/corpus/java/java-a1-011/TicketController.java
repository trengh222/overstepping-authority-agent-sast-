package com.bac.java_a1_011;

import java.util.Map;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tickets")
public class TicketController {

    private final TicketService ticketService;

    public TicketController(TicketService ticketService) {
        this.ticketService = ticketService;
    }

    @PutMapping("/{ticketId}")
    public Map<String, Object> update(@PathVariable("ticketId") Long ticketId,
                                      @RequestBody TicketUpdate update) {
        ticketService.updateTicket(ticketId, update.getTitle(), update.getPriority());
        return ticketService.findById(ticketId);
    }

    public static class TicketUpdate {

        private String title;
        private String priority;

        public String getTitle() {
            return title;
        }

        public void setTitle(String title) {
            this.title = title;
        }

        public String getPriority() {
            return priority;
        }

        public void setPriority(String priority) {
            this.priority = priority;
        }
    }
}
