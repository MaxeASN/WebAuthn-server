package com.mih.webauthn.demo.config;

import com.mih.webauthn.demo.constant.ERC4337Const;
import com.mih.webauthn.demo.domain.Transaction;
import com.mih.webauthn.demo.domain.TransactionRepo;
import com.mih.webauthn.demo.service.FidoService;
import com.mih.webauthn.demo.service.TransactionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.*;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.http.HttpService;

import javax.annotation.PostConstruct;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

@Configuration
public class Web3jConfig {
//    @Autowired
//    private Web3j web3j;

    @Bean
    public Web3j initWeb3j(){
//        Web3j web3j = Web3j.build(new HttpService("https://sepolia.infura.io/v3/ba60b163f0ad4e3a8f0c051511011cbd"));
//        Web3j web3j = Web3j.build(new HttpService("http://localhost:8545"));
//        Web3j web3j = Web3j.build(new HttpService("https://opt-goerli.g.alchemy.com/v2/o6trAJdz5w07mPyRtfSMK94KR4SMlDhw"));
        Web3j web3j = Web3j.build(new HttpService("https://aspark.space/arbrpc"));
//        Web3j web3j = Web3j.build(new HttpService("https://goerli.infura.io/v3/ba60b163f0ad4e3a8f0c051511011cbd"));

        //添加要监听事件的主题，和合约地址
//        EthFilter filter = new EthFilter(DefaultBlockParameterName.EARLIEST, DefaultBlockParameterName.LATEST, ERC4337Const.ENTRYPOINT_ADDRESS);
//        Event event = new Event("UserOperationEvent", Arrays.asList(
//                new TypeReference<Bytes32>() {},
//                new TypeReference<Address>() {},
//                new TypeReference<Address>() {},
//                new TypeReference<Uint256>() {},
//                new TypeReference<Bool>() {},
//                new TypeReference<Uint256>() {},
//                new TypeReference<Uint256>() {}));
//        String eventEncode = EventEncoder.encode(event);
//        System.out.println(eventEncode);
//        filter.addSingleTopic(eventEncode);
//        web3j.ethLogFlowable(filter).subscribe(log -> {
//            String transactionHash = log.getTransactionHash();
//            System.out.println(transactionHash);
//        });
        return web3j;
    }


//    @PostConstruct
//    public void monitorTransactionEvent(){
//        fidoService.monitorTransaction(web3j);
//    }
}
