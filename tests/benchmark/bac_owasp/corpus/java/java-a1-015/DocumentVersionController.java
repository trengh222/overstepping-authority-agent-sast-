package com.bac.java_a1_015;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/documents")
public class DocumentVersionController {

    private final DocumentVersionMapper documentVersionMapper;

    public DocumentVersionController(DocumentVersionMapper documentVersionMapper) {
        this.documentVersionMapper = documentVersionMapper;
    }

    @GetMapping("/{docId}/versions/{versionId}")
    public Map<String, Object> version(@PathVariable("docId") Long docId,
                                       @PathVariable("versionId") Long versionId) {
        return documentVersionMapper.selectVersion(docId, versionId);
    }
}
