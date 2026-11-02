package com.bac.gen.documents_neg;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1 负例：查询在 service 层绑定当前登录用户。 */
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    @Resource
    private DocumentService documentsService;

    @GetMapping("/{id}")
    public Document detail(@PathVariable("id") Long id) {
        Long uid = CurrentUser.id();
        return documentsService.getByIdAndUserId(id, uid);
    }
}
