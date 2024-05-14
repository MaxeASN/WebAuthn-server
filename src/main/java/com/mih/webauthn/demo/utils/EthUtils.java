package com.mih.webauthn.demo.utils;

import com.google.common.collect.ImmutableList;
import com.mih.webauthn.demo.constant.BlockchainConst;
import com.mih.webauthn.demo.domain.Wallet;
import com.mih.webauthn.demo.exception.TransactionFailedException;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicHierarchy;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.wallet.DeterministicSeed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.*;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@Component
public class EthUtils {
    @Autowired
    private Web3j web3j;

    private final static String transactionContractAddr = "0x3388055a762074cd417481b0acc7ed1dd944c71f";

    private final static String transactionMethodName = "test2";

    private final static ImmutableList<ChildNumber> BIP44_ETH_ACCOUNT_ZERO_PATH =
            ImmutableList.of(new ChildNumber(44, true), new ChildNumber(60, true),
                    ChildNumber.ZERO_HARDENED, ChildNumber.ZERO);

    public String sendTransactionTol2(Wallet wallet, String toAddress, BigDecimal amount) throws IOException {
        BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
        BigInteger amountWei = Convert.toWei(String.valueOf(amount), Convert.Unit.ETHER).toBigInteger();

        //用以太坊私钥签名交易,发送给合约
        List<Type> inputParameters = new ArrayList<>();
        List<TypeReference<?>> outputParameters = new ArrayList<>();
        String signData = Numeric.toHexString(signTransaction(wallet, toAddress, amountWei, gasPrice));
        Utf8String transactionBytes = new Utf8String(signData);
        inputParameters.add(transactionBytes);
        //输出参数暂时给个空数组
//        TypeReference<Bool> typeReference = new TypeReference<Bool>() {
//        };
//        outputParameters.add(typeReference);
        Function function = new Function(transactionMethodName, inputParameters, Collections.emptyList());
        String data = FunctionEncoder.encode(function);
        return sendContract(wallet, transactionContractAddr, gasPrice, data);
    }

    @Deprecated
    public List<Type> ethCall(String contractAddr, Function function) throws IOException {
        //编码构建的函数
        String data = FunctionEncoder.encode(function);
        // 创建EthCall请求对象
        EthCall ethCall = web3j.ethCall(
                        Transaction.createEthCallTransaction(null, contractAddr, data),
                        DefaultBlockParameterName.LATEST)
                .send();
        // 从响应中解码函数执行结果
        List<Type> results = FunctionReturnDecoder.decode(
                ethCall.getValue(), function.getOutputParameters());
        return results;
    }

    public List<Type> ethCall(String contractAddr, String methodName, List<Type> inputParams, List<TypeReference<?>> outputParams) throws IOException {
        Function function = new Function(methodName, inputParams, outputParams);
        //编码构建的函数
        String data = FunctionEncoder.encode(function);
        // 创建EthCall请求对象
        EthCall ethCall = web3j.ethCall(
                        Transaction.createEthCallTransaction(null, contractAddr, data),
                        DefaultBlockParameterName.LATEST)
                .send();
        // 从响应中解码函数执行结果
        List<Type> results = FunctionReturnDecoder.decode(
                ethCall.getValue(), function.getOutputParameters());
        return results;
    }

    @Deprecated
    public String sendContract(Wallet wallet, String contractAddr, BigInteger gasPrice, String data) throws IOException {
        BigInteger nonce = web3j.ethGetTransactionCount(wallet.getAddress(),
                        DefaultBlockParameterName.PENDING).send()
                .getTransactionCount();
        BigInteger gasLimit = web3j
                .ethEstimateGas(
                        new org.web3j.protocol.core.methods.request.Transaction(wallet.getAddress(), null, null,
                                null, contractAddr, null, data)).send().getAmountUsed();
        RawTransaction rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                gasLimit,
                contractAddr,
                data);
        Credentials credentials = Credentials.create(AESUtils.decrypt(wallet.getPrivateKey()));
        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, 10L, credentials);
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(Numeric.toHexString(signedMessage)).send();
        return ethSendTransaction.getTransactionHash();
    }

    public String sendContract(Wallet wallet, String contractAddr, String methodName, List<Type> inputParams, List<TypeReference<?>> outputParams) throws IOException, TransactionFailedException {
        BigInteger nonce = web3j.ethGetTransactionCount(wallet.getAddress(),
                        DefaultBlockParameterName.PENDING).send().getTransactionCount();
        BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
        Function function = new Function(methodName, inputParams, outputParams);
        String data = FunctionEncoder.encode(function);
        BigInteger gasLimit = new BigInteger("10000000");

        RawTransaction rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                gasLimit,
                contractAddr,
                data);
        Credentials credentials = Credentials.create(AESUtils.decrypt(wallet.getPrivateKey()));
        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, BlockchainConst.CHAIN_ID, credentials);
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(Numeric.toHexString(signedMessage)).send();
        if(ethSendTransaction.hasError()){
            throw new TransactionFailedException("调用4337合约失败");
        }
        return ethSendTransaction.getTransactionHash();
    }
    private byte[] signTransaction(Wallet wallet, String toAddress, BigInteger amountWei, BigInteger gasPrice) throws IOException {
        BigInteger nonce = web3j.ethGetTransactionCount(wallet.getAddress(),
                        DefaultBlockParameterName.PENDING).send().getTransactionCount();
        BigInteger gasLimit = web3j
                .ethEstimateGas(
                        new org.web3j.protocol.core.methods.request.Transaction(wallet.getAddress(), null, null,
                                null, toAddress, amountWei, null)).send().getAmountUsed();
        RawTransaction rawTransaction = RawTransaction.createTransaction(nonce, gasPrice, gasLimit, toAddress, amountWei, "");
        return TransactionEncoder.signMessage(rawTransaction, 10L, Credentials.create(AESUtils.decrypt(wallet.getPrivateKey())));
    }

    public String createPrivateKey(long userId) {
        DeterministicSeed deterministicSeed = new DeterministicSeed(new SecureRandom(), 128, "", System.currentTimeMillis() / 1000);
        String mnemonic = deterministicSeed.getMnemonicCode().toString();
        byte[] seed = MnemonicUtils.generateSeed(mnemonic, "");

        DeterministicKey rootKey = HDKeyDerivation.createMasterPrivateKey(seed);
        DeterministicHierarchy hierarchy = new DeterministicHierarchy(rootKey);

        DeterministicKey deterministicKey = hierarchy.deriveChild(BIP44_ETH_ACCOUNT_ZERO_PATH, false, true, new ChildNumber((int) userId, false));
        return deterministicKey.getPrivKey().toString(16);
    }

    public String getAddressFromPrivateKey(String privateKey) {
        Credentials credentials = Credentials.create(privateKey);
        return credentials.getAddress();
    }

    public List<String> sendGasFee(String... toAddressArray) {
        try {
            CountDownLatch count = new CountDownLatch(toAddressArray.length);
            List<String> transactionHashList = new ArrayList<>();
            BigInteger nonce = web3j.ethGetTransactionCount(BlockchainConst.MINER_ADDRESS, DefaultBlockParameterName.LATEST).send().getTransactionCount();
            for (int i=0;i<toAddressArray.length;i++) {
                String toAddress = toAddressArray[i];
                nonce = nonce.add(new BigInteger(String.valueOf(i)));
                BigInteger value = Convert.toWei("10", Convert.Unit.ETHER).toBigInteger(); // 转移金额为1ETH（单位为wei）
                // 从以太坊网络获取最新的nonce值
                System.out.println(nonce);
                BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
                BigInteger gasLimit = web3j.ethEstimateGas(new Transaction(BlockchainConst.MINER_ADDRESS, null, null, null, toAddress, value, null)).send().getAmountUsed();
                // 创建一个转账交易对象并签名
                RawTransaction rawTransaction = RawTransaction.createEtherTransaction(BlockchainConst.CHAIN_ID, nonce, gasLimit, toAddress, value, BigInteger.ZERO, gasPrice);
                String privateKey = AESUtils.decrypt(BlockchainConst.MINER_PRIVATE_KEY);
                Credentials credential = Credentials.create(privateKey);
                byte[] signMessage = TransactionEncoder.signMessage(rawTransaction, credential);
                web3j.ethSendRawTransaction(Numeric.toHexString(signMessage)).sendAsync().thenAccept((EthSendTransaction ethSendTransaction)->{
                    transactionHashList.add(ethSendTransaction.getTransactionHash());
                    count.countDown();
                });
            }
            count.await();
            return transactionHashList;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void confirmTransaction(String... txHashes) throws InterruptedException {
        CountDownLatch count = new CountDownLatch(txHashes.length);
        for(String txHash : txHashes){
            CompletableFuture.runAsync(()->{
                boolean isPacked = false;
                while (!isPacked) {
                    try {
                        // 先异步获取交易回执
                        EthGetTransactionReceipt txReceipt = web3j.ethGetTransactionReceipt(txHash).sendAsync().get();
                        if (txReceipt != null && txReceipt.getTransactionReceipt().isPresent()) {
                            // 交易已经被打包
                            isPacked = true;
                            count.countDown();
                        } else {
                            Thread.sleep(300);
                        }
                    } catch (Exception e) {
                        //TODO:处理多线程出错的问题
                        isPacked = true;
                        count.countDown();
                    }
                }
            });
        }
        count.await(1, TimeUnit.MINUTES);
    }
}
