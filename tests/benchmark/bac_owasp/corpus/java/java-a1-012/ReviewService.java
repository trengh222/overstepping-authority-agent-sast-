package com.bac.java_a1_012;

import java.util.Map;

import org.springframework.stereotype.Service;

@Service
public class ReviewService {

    private final ReviewMapper reviewMapper;

    public ReviewService(ReviewMapper reviewMapper) {
        this.reviewMapper = reviewMapper;
    }

    public Map<String, Object> loadReview(Long reviewId) {
        return reviewMapper.selectReview(reviewId);
    }
}
