package com.bac.gen.documents_pos;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1：路径参数 id 直接查库并返回，没有任何归属校验。 */
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    @Resource
    private DocumentService documentsService;

    @GetMapping("/{id}")
    public Document detail(@PathVariable("id") Long id) {
        return documentsService.getById(id);
    }
}
