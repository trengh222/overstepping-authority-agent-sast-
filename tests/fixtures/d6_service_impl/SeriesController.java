package com.example.shop;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** D6 正样本：controller → SeriesService（接口）→ SeriesServiceImpl → SeriesMapper。 */
@RestController
@RequestMapping("/api/series")
public class SeriesController {

    @Autowired
    private SeriesService seriesService;

    @GetMapping("/{id}")
    public Object load(@PathVariable("id") Long id) {
        return seriesService.load(id);
    }
}
