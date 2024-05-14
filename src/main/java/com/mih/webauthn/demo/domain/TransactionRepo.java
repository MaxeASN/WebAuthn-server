package com.mih.webauthn.demo.domain;

import com.mih.webauthn.demo.controller.response.CommonResult;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import javax.persistence.OrderBy;
import java.util.List;

public interface TransactionRepo extends CrudRepository<Transaction, Integer> {
    @Query("SELECT t FROM Transaction t WHERE t.appUserId = :appUserId order by t.createTime desc")
    List<Transaction> findAllByAppUserId(long appUserId);

    Transaction findByHash(String transactionHash);
}
