package com.bac.java_a1_008;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reports")
public class ReportExportController {

    private final ReportService reportService;

    public ReportExportController(ReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping("/export")
    public ResponseEntity<String> export(@RequestParam("reportId") Long reportId) {
        String csv = reportService.exportCsv(reportId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=report.csv")
                .body(csv);
    }
}
