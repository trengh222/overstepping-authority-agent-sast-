package com.bac.java_a1_007;

import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

@Service
public class CartService {

    private final CartMapper cartMapper;

    public CartService(CartMapper cartMapper) {
        this.cartMapper = cartMapper;
    }

    public List<Map<String, Object>> loadItems(List<Long> itemIds) {
        return cartMapper.selectByIds(itemIds);
    }
}
