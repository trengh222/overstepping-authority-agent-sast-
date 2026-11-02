package com.bac.java_a1_023;

import org.springframework.stereotype.Component;

@Component("reviewAccess")
public class ReviewAccess {

    private final ReviewMapper reviewMapper;

    public ReviewAccess(ReviewMapper reviewMapper) {
        this.reviewMapper = reviewMapper;
    }

    public boolean canRead(Long reviewId, String username) {
        Integer owned = reviewMapper.countOwnedByUsername(reviewId, username);
        return owned != null && owned > 0;
    }
}
