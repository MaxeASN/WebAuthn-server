package com.mih.webauthn.demo.service;

import com.mih.webauthn.demo.domain.dto.L1RpcParams;
import com.mih.webauthn.demo.domain.dto.L1RpcResponse;
import feign.RequestLine;
import org.springframework.web.bind.annotation.RequestBody;

//@FeignClient(fallback = L1RpcHystrix.class)
public interface L1RpcService {
    @RequestLine("POST /")
    L1RpcResponse maxeRegistL1(@RequestBody L1RpcParams params);

    @RequestLine("POST /")
    L1RpcResponse importRawKey(@RequestBody L1RpcParams params);
}
