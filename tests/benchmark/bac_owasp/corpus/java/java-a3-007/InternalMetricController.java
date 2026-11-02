package com.bac.java_a3_007;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal")
public class InternalMetricController {

    @GetMapping("/metrics/detail")
    public Map<String, Object> detail() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("threads", Thread.activeCount());
        result.put("freeMemory", Runtime.getRuntime().freeMemory());
        result.put("region", "cn-east-1");
        return result;
    }
}
