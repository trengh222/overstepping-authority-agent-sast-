package com.bac.java_a3_005;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sys/db")
public class SysDbPoolController {

    @Value("${spring.datasource.url}")
    private String datasourceUrl;

    @Value("${spring.datasource.username}")
    private String datasourceUsername;

    @Value("${spring.datasource.password}")
    private String datasourcePassword;

    @GetMapping("/pool")
    public Map<String, Object> pool() {
        return Map.<String, Object>of(
                "url", datasourceUrl,
                "username", datasourceUsername,
                "password", datasourcePassword,
                "maxActive", 32);
    }
}
