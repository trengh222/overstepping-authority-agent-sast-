package com.example.shop;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** D6 正样本：userId 经 setter 写入查询对象，对象再跨过程流入 Mapper。 */
@RestController
@RequestMapping("/statisticsInfo")
public class StatisticsController {

    @Autowired
    private StatisticsService statisticsService;

    @GetMapping("/loadDataList")
    public Object load(Long userId) {
        Query query = new Query();
        query.setUserId(userId);
        return statisticsService.findListByPage(query);
    }

    // D6：无注解查询对象（StatisticsInfoQuery）作为客户端可控污点源
    @GetMapping("/loadDataListQuery")
    public Object loadByQuery(StatisticsInfoQuery query) {
        return statisticsService.findListByPage(query);
    }

    // 未鉴权写：add 前缀 → privilege_op=true，无任何鉴权 → A3
    @PostMapping("/add")
    public Object add(StatisticsInfo bean) {
        statisticsService.add(bean);
        return null;
    }
}
