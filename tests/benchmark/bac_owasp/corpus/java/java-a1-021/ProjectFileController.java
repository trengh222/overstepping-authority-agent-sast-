package com.bac.java_a1_021;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/projects")
public class ProjectFileController {

    private final ProjectFileService projectFileService;

    public ProjectFileController(ProjectFileService projectFileService) {
        this.projectFileService = projectFileService;
    }

    @GetMapping("/{projectId}/files/{fileId}")
    public ResponseEntity<Object> file(@PathVariable("projectId") Long projectId,
                                       @PathVariable("fileId") Long fileId,
                                       HttpSession session) {
        Long currentUserId = (Long) session.getAttribute("LOGIN_USER_ID");
        if (!projectFileService.ownsProject(projectId, currentUserId)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(projectFileService.loadFile(projectId, fileId));
    }
}
