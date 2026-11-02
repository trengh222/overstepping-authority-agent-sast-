package com.bac.gen.files_pos;

/** 无所有权过滤：按主键直接取。 */
public class FileRecordService {

    public FileRecord getById(Long id) {
        return FileRecordMapper.selectById(id);
    }
}
