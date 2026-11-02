package com.bac.java_a1_025;

import java.util.List;

import org.springframework.stereotype.Service;

@Service
public class CartService {

    private final CartMapper cartMapper;

    public CartService(CartMapper cartMapper) {
        this.cartMapper = cartMapper;
    }

    public int removeOwned(List<Long> itemIds, Long userId) {
        if (itemIds == null || itemIds.isEmpty()) {
            return 0;
        }
        return cartMapper.deleteOwned(itemIds, userId);
    }
}
