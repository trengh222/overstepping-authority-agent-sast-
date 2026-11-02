package com.bac.java_a1_019;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private final DocumentMapper documentMapper;

    public DocumentController(DocumentMapper documentMapper) {
        this.documentMapper = documentMapper;
    }

    @GetMapping("/{docId}")
    public Map<String, Object> detail(@PathVariable("docId") Long docId, HttpSession session) {
        Long currentUserId = (Long) session.getAttribute("LOGIN_USER_ID");
        return documentMapper.selectOwned(docId, currentUserId);
    }
}
