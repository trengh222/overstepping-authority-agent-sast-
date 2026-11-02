package com.bac.java_a1_010;

import java.util.Map;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/addresses")
public class AddressController {

    private final AddressMapper addressMapper;

    public AddressController(AddressMapper addressMapper) {
        this.addressMapper = addressMapper;
    }

    @DeleteMapping("/{addressId}")
    public Map<String, Object> remove(@PathVariable("addressId") Long addressId) {
        addressMapper.deleteById(addressId);
        return Map.<String, Object>of("deleted", addressId);
    }
}
