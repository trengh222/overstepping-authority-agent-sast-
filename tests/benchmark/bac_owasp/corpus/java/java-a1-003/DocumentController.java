package com.bac.java_a1_003;

import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private final DocumentService documentService;

    public DocumentController(DocumentService documentService) {
        this.documentService = documentService;
    }

    @PostMapping("/rename")
    public Map<String, Object> rename(@RequestBody RenameRequest request) {
        return documentService.rename(request.getDocId(), request.getNewName());
    }

    public static class RenameRequest {

        private Long docId;
        private String newName;

        public Long getDocId() {
            return docId;
        }

        public void setDocId(Long docId) {
            this.docId = docId;
        }

        public String getNewName() {
            return newName;
        }

        public void setNewName(String newName) {
            this.newName = newName;
        }
    }
}
