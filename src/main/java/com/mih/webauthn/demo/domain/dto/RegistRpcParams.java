package com.mih.webauthn.demo.domain.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class RegistRpcParams {

    private String name;


    private String avatar;


    private String email;
}
