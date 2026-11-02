package com.bac.java_a3_009;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/ops")
public class InternalOpsController {

    @PostMapping("/restart")
    @PreAuthorize("hasAnyRole('ADMIN', 'OPS')")
    public Map<String, Object> restart(@RequestParam("service") String service) {
        return Map.<String, Object>of("service", service, "status", "RESTARTING");
    }
}
