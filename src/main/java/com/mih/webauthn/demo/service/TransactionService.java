package com.mih.webauthn.demo.service;

import com.mih.webauthn.demo.domain.Transaction;
import com.mih.webauthn.demo.domain.vo.TransactionDetails;

import javax.persistence.OrderBy;
import java.util.List;

public interface TransactionService {

    List<Transaction> findAllByAppUserId(long appUserId, int pageNum, int pageSize);

    Long findL1AddressIdByAddress(String fromAddress);

    //验证fromAddress是否是用户的l1地址
    boolean verifyFromAddress(String fromAddress, Long userId);

    TransactionDetails getTransactionDetailsById(Integer transactionId);

}
