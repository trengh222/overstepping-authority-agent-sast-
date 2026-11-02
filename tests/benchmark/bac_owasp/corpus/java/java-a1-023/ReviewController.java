package com.bac.java_a1_023;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reviews")
public class ReviewController {

    private final ReviewMapper reviewMapper;

    public ReviewController(ReviewMapper reviewMapper) {
        this.reviewMapper = reviewMapper;
    }

    @GetMapping("/{reviewId}")
    @PreAuthorize("@reviewAccess.canRead(#reviewId, authentication.name)")
    public Map<String, Object> detail(@PathVariable("reviewId") Long reviewId) {
        return reviewMapper.selectReview(reviewId);
    }
}
