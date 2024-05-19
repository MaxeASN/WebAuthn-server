package com.mih.webauthn.demo.service;

import feign.Feign;
import feign.Request;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class RpcService {
    @Bean(name = "l1RpcService")
    public L1RpcService createL1RpcService(){
        return Feign.builder()
                .encoder(new JacksonEncoder())
                .decoder(new JacksonDecoder())
                .options(new Request.Options(3L, TimeUnit.SECONDS, 5L, TimeUnit.SECONDS, true))
                .target(L1RpcService.class, "http://172.31.226.166:27890");
    }

}


