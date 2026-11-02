package com.bac.gen.documents_neg;

/** 归属过滤：id + userId 双条件。 */
public class DocumentService {

    public Document getByIdAndUserId(Long id, Long userId) {
        return DocumentMapper.selectByIdAndUserId(id, userId);
    }
}
