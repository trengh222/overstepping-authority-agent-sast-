package com.example.shop.service;

import com.example.shop.repo.OrderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OrderService {

    @Autowired
    private OrderRepository orderRepository;

    public Object findById(Long id) {
        return orderRepository.findById(id).orElse(null);
    }

    public Object findByUserIdAndId(String userId, Long id) {
        return orderRepository.findByUserIdAndId(userId, id);
    }
}