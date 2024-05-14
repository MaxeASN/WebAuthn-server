package com.mih.webauthn.demo.service;

import com.mih.webauthn.demo.domain.Wallet;
import org.web3j.protocol.Web3j;

public interface FidoService {
    /**
     *
     * @param userId 用户id
     * @return 以太坊地址
     */
    Wallet registerAddressAndPrivateKey(long userId);

    void monitorTransaction(Web3j web3j);

    void registerL1Address(Long appUserId, String address);
}
