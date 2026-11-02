package com.bac.java_a3_010;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sys/db")
public class SysDbController {

    @Value("${spring.datasource.password}")
    private String datasourcePassword;

    @GetMapping("/pool")
    public Map<String, Object> pool() {
        return Map.<String, Object>of("pool", "HikariCP", "password", datasourcePassword, "maxPoolSize", 20);
    }
}
