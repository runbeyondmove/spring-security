package com.example.demo.security;

import cn.mrcode.imooc.springsecurity.securitycore.authorize.AuthorizeConfigProvider;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.stereotype.Component;

/**
 * 权限配置
 *
 * @author : zhuqiang
 * @version : V1.0
 * @date : 2018/8/12 21:25
 */
@Component
@Order(Integer.MAX_VALUE)  // 注意优先级要比通用的权限配置低，值越高优先级越低
public class DemoAuthorizeConfigProvider implements AuthorizeConfigProvider {
    @Override
    public void config(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config) {
        config.antMatchers(
                "/user/regist", // 注册请求
                // org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController
                // BasicErrorController 类提供的默认错误信息处理服务
                "/error",
                "/connect/*",
                "/auth/*",
                "/signin",
                "/social/signUp",  // app注册跳转服务
                "/swagger-ui.html",
                "/swagger-ui.html/**",
                "/webjars/**",
                "/swagger-resources/**",
                "/v2/**"
        )
                .permitAll();
        config.anyRequest().access("@rbacService.hasPermission(request,authentication)");
    }
}
