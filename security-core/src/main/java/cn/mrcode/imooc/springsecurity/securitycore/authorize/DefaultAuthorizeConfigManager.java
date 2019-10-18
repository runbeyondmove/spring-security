package cn.mrcode.imooc.springsecurity.securitycore.authorize;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 默认的权限配置管理
 *
 * @author : zhuqiang
 * @version : V1.0
 * @date : 2018/8/12 21:21
 */
@Component
public class DefaultAuthorizeConfigManager implements AuthorizeConfigManager {

    /**
     * Spring启动时自动扫描所有的AuthorizeConfigProvider,自动注入
     */
    @Autowired
    private List<AuthorizeConfigProvider> authorizeConfigProviders;

    @Override
    public void config(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config) {
        for (AuthorizeConfigProvider provider : authorizeConfigProviders) {
            provider.config(config);
        }
        // 除了上面配置的，其他的都需要登录后才能访问
       config.anyRequest().authenticated();
    }

    // @Override
    // public void config(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config) {
    //     boolean existAnyRequestConfig = false;
    //     String existAnyRequestConfigName = null;
    //
    //     for (AuthorizeConfigProvider authorizeConfigProvider : authorizeConfigProviders) {
    //         boolean currentIsAnyRequestConfig = authorizeConfigProvider.config(config);
    //         if (existAnyRequestConfig && currentIsAnyRequestConfig) {
    //             throw new RuntimeException("重复的anyRequest配置:" + existAnyRequestConfigName + ","
    //                 + authorizeConfigProvider.getClass().getSimpleName());
    //         } else if (currentIsAnyRequestConfig) {
    //             existAnyRequestConfig = true;
    //             existAnyRequestConfigName = authorizeConfigProvider.getClass().getSimpleName();
    //         }
    //     }
    //
    //     if(!existAnyRequestConfig){
    //         config.anyRequest().authenticated();
    //     }
    // }
}
