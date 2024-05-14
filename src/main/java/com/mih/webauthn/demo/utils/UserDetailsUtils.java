package com.mih.webauthn.demo.utils;

import org.bitcoinj.net.discovery.HttpDiscovery;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class UserDetailsUtils {
    /**
     * SpringSecurity根据上下文获取UserDetails
     * @return
     */
    public UserDetails getUserDetails(){
        UserDetails user = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            user = (UserDetails) authentication.getPrincipal();
            // 使用user对象进行操作
        }
        return user;
    }
}
