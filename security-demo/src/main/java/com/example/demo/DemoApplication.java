package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication(scanBasePackages =
        {
                "com.example.demo",
                "cn.mrcode.imooc.springsecurity.securitybrowser",
                // "cn.mrcode.imooc.springsecurity.securityapp",
                "cn.mrcode.imooc.springsecurity.securitycore",
                "cn.mrcode.imooc.springsecurity.securityauthorize"
        })
//@SpringBootApplication
@RestController
@EnableSwagger2
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @GetMapping("/hello")
    public String hello() {
        return "hello spring security";
    }
}
