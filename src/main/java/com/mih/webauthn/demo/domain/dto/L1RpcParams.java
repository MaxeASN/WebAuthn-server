package com.mih.webauthn.demo.domain.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class L1RpcParams {
    @JsonProperty("jsonrpc")
    private String jsonrpc = "2.0";

    @JsonProperty("id")
    private int id = 2;

    @JsonProperty("method")
    private String method;

    @JsonProperty("params")
    private Object[] params;

    public static L1RpcParams registerL1Params(int chainId, String accountAddress) {
        L1RpcParams l1RpcParams = new L1RpcParams();
        l1RpcParams.method = "maxe_registL1";
        l1RpcParams.params = new Object[2];
        l1RpcParams.params[0] = chainId;
        l1RpcParams.params[1] = accountAddress;
        return l1RpcParams;
    }

    public static L1RpcParams importRawKeyParams(int chainId, String privateKey){
        L1RpcParams l1RpcParams = new L1RpcParams();
        l1RpcParams.method = "maxe_importRawKey";
        l1RpcParams.params = new Object[2];
        l1RpcParams.params[0] = chainId;
        l1RpcParams.params[1] = privateKey;
        return l1RpcParams;
    }
}
