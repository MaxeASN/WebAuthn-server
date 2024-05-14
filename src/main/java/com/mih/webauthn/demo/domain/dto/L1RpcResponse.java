package com.mih.webauthn.demo.domain.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
public class L1RpcResponse {
    @JsonProperty("jsonrpc")
    private String jsonrpc;

    @JsonProperty("id")
    private int id;

    @JsonProperty("method")
    private String method = "maxe_registL1";

    @JsonProperty("result")
    private Result result;

    @JsonProperty("error")
    private Error error;

    @Data
    @NoArgsConstructor
    public static class Result {
        @JsonProperty("l1Address")
        private String l1Address;

        @JsonProperty("l2Account")
        private String l2Account;

        public Result(String successMsg){

        }
    }

    @Data
    public static class Error {
        @JsonProperty("code")
        private int code;

        @JsonProperty("message")
        private String message;
    }

}
