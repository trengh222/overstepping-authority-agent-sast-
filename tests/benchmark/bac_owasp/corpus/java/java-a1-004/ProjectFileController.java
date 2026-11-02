package com.bac.java_a1_004;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects")
public class ProjectFileController {

    private final FileService fileService;

    public ProjectFileController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/{projectId}/files/{fileId}")
    public Map<String, Object> file(@PathVariable("projectId") Long projectId,
                                    @PathVariable("fileId") Long fileId) {
        return fileService.load(projectId, fileId);
    }
}
