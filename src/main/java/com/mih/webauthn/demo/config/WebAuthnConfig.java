package com.mih.webauthn.demo.config;

import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebAuthnConfig {
    @Bean
    public ConcurrentMapCache newCacheMap(){
        return new ConcurrentMapCache("myCache");
    }
}
