package com.example.app;

import com.example.other.ImportedController;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

/** 注册可达正样本：控制器在扫描根之外，但被 @Import 显式引入 → 已注册。 */
@SpringBootApplication(scanBasePackages = "com.example.app")
@Import(ImportedController.class)
public class Application {
}
