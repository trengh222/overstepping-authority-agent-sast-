package com.bac.gen.documents_pos;

/** 无所有权过滤：按主键直接取。 */
public class DocumentService {

    public Document getById(Long id) {
        return DocumentMapper.selectById(id);
    }
}
