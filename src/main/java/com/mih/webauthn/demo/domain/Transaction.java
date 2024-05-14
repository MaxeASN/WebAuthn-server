package com.mih.webauthn.demo.domain;

//import com.mih.webauthn.demo.constant.TransactionConst;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
public class Transaction {
    @Id
    @GeneratedValue
    private Integer id;

    private Long appUserId;

    private String chainId;

    private Integer coin;

    @Column(name = "l1_address_id")
    private Long l1AddressId;

    private String toAddress;

    private BigDecimal amount;

    private String hash;

    private Integer seqNum;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;

    public Transaction(Long appUserId, String chainId, Integer coin, Long l1AddressId, String toAddress, BigDecimal amount, String hash) {
        this.appUserId = appUserId;
        this.chainId = chainId;
        this.coin = coin;
        this.l1AddressId = l1AddressId;
        this.toAddress = toAddress;
        this.amount = amount;
        this.hash = hash;
        this.createTime = LocalDateTime.now();
        this.updateTime = LocalDateTime.now();
    }
}
