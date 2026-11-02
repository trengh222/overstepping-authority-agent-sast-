package com.bac.gen.files_pos;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1：路径参数 id 直接查库并返回，没有任何归属校验。 */
@RestController
@RequestMapping("/api/files")
public class FileRecordController {

    @Resource
    private FileRecordService filesService;

    @GetMapping("/{id}")
    public FileRecord detail(@PathVariable("id") Long id) {
        return filesService.getById(id);
    }
}
