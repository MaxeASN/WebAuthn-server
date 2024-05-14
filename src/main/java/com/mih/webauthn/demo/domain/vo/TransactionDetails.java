package com.mih.webauthn.demo.domain.vo;

import com.mih.webauthn.demo.domain.Transaction;
import com.mih.webauthn.demo.utils.CommonUtils;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@NoArgsConstructor
public class TransactionDetails {

    String chain;

    String from;

    String to;

    String symbol;

    BigDecimal amount;

    String l2Hash;

    public TransactionDetails(Transaction transaction, String from){
        this.chain = CommonUtils.chainId2name(transaction.getChainId());
        this.from = from;
        this.to = transaction.getToAddress();
        this.symbol = CommonUtils.coinId2Name(transaction.getCoin());
        this.amount = transaction.getAmount();
        this.l2Hash = transaction.getHash();
    }

}
