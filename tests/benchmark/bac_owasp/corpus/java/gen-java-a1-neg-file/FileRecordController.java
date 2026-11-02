package com.bac.gen.files_neg;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1 负例：查询在 service 层绑定当前登录用户。 */
@RestController
@RequestMapping("/api/files")
public class FileRecordController {

    @Resource
    private FileRecordService filesService;

    @GetMapping("/{id}")
    public FileRecord detail(@PathVariable("id") Long id) {
        Long uid = CurrentUser.id();
        return filesService.getByIdAndUserId(id, uid);
    }
}
