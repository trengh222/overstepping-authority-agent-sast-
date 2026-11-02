package com.bac.java_a1_025;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/cart")
public class CartController {

    private final CartService cartService;

    public CartController(CartService cartService) {
        this.cartService = cartService;
    }

    @PostMapping("/items/batch/remove")
    public Map<String, Object> removeBatch(@RequestBody List<Long> itemIds, HttpSession session) {
        Long currentUserId = (Long) session.getAttribute("LOGIN_USER_ID");
        int removed = cartService.removeOwned(itemIds, currentUserId);
        return Map.<String, Object>of("removed", removed);
    }
}
