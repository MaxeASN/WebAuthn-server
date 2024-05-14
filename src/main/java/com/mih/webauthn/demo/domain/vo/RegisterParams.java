package com.mih.webauthn.demo.domain.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterParams {
    private String faceData;

    private String username;

    private String registrationAddToken;

    private String recoveryToken;
}
