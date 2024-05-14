package com.mih.webauthn.demo.domain.dto;

import com.mih.webauthn.demo.domain.vo.TransactionParams;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@NoArgsConstructor
public class CacheTransactionParams {
    private int coin;

    private String toAddress;

    private BigDecimal amount;

    private byte[] credentialId;

    public CacheTransactionParams(TransactionParams transactionParams, byte[] credentialId){
        this.coin = transactionParams.getCoin();
        this.toAddress = transactionParams.getToAddress();
        this.amount = transactionParams.getAmount();
        this.credentialId = credentialId;
    }
}
