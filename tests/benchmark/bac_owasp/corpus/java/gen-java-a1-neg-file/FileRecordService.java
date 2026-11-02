package com.bac.gen.files_neg;

/** 归属过滤：id + userId 双条件。 */
public class FileRecordService {

    public FileRecord getByIdAndUserId(Long id, Long userId) {
        return FileRecordMapper.selectByIdAndUserId(id, userId);
    }
}
