package com.mih.webauthn.demo.service.impl;

import com.mih.webauthn.demo.constant.ERC4337Const;
import com.mih.webauthn.demo.domain.L1Address;
import com.mih.webauthn.demo.domain.L1AddressRepo;
import com.mih.webauthn.demo.domain.Wallet;
import com.mih.webauthn.demo.domain.WalletRepo;
import com.mih.webauthn.demo.service.FidoService;
import com.mih.webauthn.demo.utils.AESUtils;
import com.mih.webauthn.demo.utils.EthUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.DynamicStruct;
import org.web3j.abi.datatypes.Event;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.EthFilter;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.Arrays;

@Service
public class FidoServiceImpl implements FidoService {
    @Autowired
    private EthUtils ethUtils;

    @Autowired
    private WalletRepo walletRepo;

    @Autowired
    private L1AddressRepo l1AddressRepo;

    @Override
    public Wallet registerAddressAndPrivateKey(long userId) {
        String privateKey = ethUtils.createPrivateKey(userId);
        String address = ethUtils.getAddressFromPrivateKey(privateKey);
        Wallet wallet = Wallet.builder()
                .appUserId(userId)
                .address(address)
                .privateKey(AESUtils.encrypt(privateKey))
                .build();
        walletRepo.save(wallet);
        return wallet;
    }

    @Override
    public void monitorTransaction(Web3j web3j) {
        EthFilter filter = new EthFilter(DefaultBlockParameter.valueOf(new BigInteger("8957745")), DefaultBlockParameterName.LATEST, ERC4337Const.TXSTATE_ADDRESS);

        filter.addSingleTopic("0x066387f39b13a8203bdbdc8377a678ce2489d9e4c1798f6b93cce980d7ab6502");
        web3j.ethLogFlowable(filter).subscribe(log -> {
            String transactionHash = log.getTransactionHash();
            System.out.println(transactionHash);
        });
    }

    @Override
    public void registerL1Address(Long appUserId, String address) {
        L1Address entity = new L1Address();
        entity.setAppUserId(appUserId);
        entity.setL1Address(address);
        entity.setCreateTime(LocalDateTime.now());
        l1AddressRepo.save(entity);
    }

}
