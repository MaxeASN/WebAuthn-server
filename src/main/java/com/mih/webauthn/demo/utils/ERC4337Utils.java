package com.mih.webauthn.demo.utils;

import com.mih.webauthn.demo.constant.ERC20Const;
import com.mih.webauthn.demo.constant.ERC4337Const;
import com.mih.webauthn.demo.domain.Wallet;
import com.mih.webauthn.demo.domain.WalletRepo;
import com.mih.webauthn.demo.domain.erc4337.UserOperation;
import com.mih.webauthn.demo.domain.vo.TransactionParams;
import com.mih.webauthn.demo.exception.EthCallException;
import com.mih.webauthn.demo.exception.TransactionFailedException;
import com.mih.webauthn.demo.exception.UserRegisterFailException;
import io.github.webauthn.domain.WebAuthnCredentialsRepository;
import io.github.webauthn.jpa.JpaWebAuthnCredentials;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.web3j.abi.DefaultFunctionEncoder;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.*;
import org.web3j.abi.datatypes.generated.*;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Component
@Slf4j
public class ERC4337Utils {
    @Autowired
    private EthUtils ethUtils;

    @Autowired
    private WalletRepo walletRepo;

    @Autowired
    private WebAuthnCredentialsRepository<JpaWebAuthnCredentials> webAuthnCredentialsRepository;

    @Autowired
    private Web3j web3j;

    private final String signUserOpAddr = "";

    public static DynamicStruct createUserOpStruct(UserOperation uo){
        List<Type> structParams = new ArrayList<>();
        structParams.add(new Address(uo.getAddress()));
        structParams.add(new Uint256(uo.getNonce()));
        structParams.add(new DynamicBytes(uo.getInitCode()));
        structParams.add(new DynamicBytes(uo.getCallData()));
        structParams.add(new Uint256(uo.getCallGasLimit()));
        structParams.add(new Uint256(uo.getVerificationGasLimit()));
        structParams.add(new Uint256(uo.getPreVerificationGas()));
        structParams.add(new Uint256(uo.getMaxFeePerGas()));
        structParams.add(new Uint256(uo.getMaxPriorityFeePerGas()));
        structParams.add(new DynamicBytes(uo.getPaymasterAndData()));
        structParams.add(new DynamicBytes(uo.getL1TxData()));
        structParams.add(new DynamicBytes(uo.getFIDOPubKey()));
        structParams.add(new DynamicBytes(uo.getSignature()));
        return new DynamicStruct(structParams);
    }

    public DynamicBytes signUserOp(Wallet wallet, StaticStruct UserOp) throws IOException {
        Function function = new Function(
                "signUserOp",
                Arrays.asList(UserOp),
                Arrays.asList(new TypeReference<Bytes32>() {})
        );
        String encodedFunction = FunctionEncoder.encode(function);
        EthCall response = web3j.ethCall(Transaction.createEthCallTransaction(wallet.getAddress(), signUserOpAddr, encodedFunction),
                        DefaultBlockParameterName.LATEST).send();
        List<Type> output = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
        return (DynamicBytes) output.get(0);
    }

    public String sendTransaction(Wallet wallet, TransactionParams transactionParams, byte[] credentialId) throws IOException, TransactionFailedException {
        JpaWebAuthnCredentials credentials = webAuthnCredentialsRepository.findByCredentialId(credentialId).get(0);
        //TODO:确认用户是否注册了
//        if(){
//            throw new UserNotRegisterAbstractAccountException();
//        }
        String accountAddress = wallet.getContractAddress();
        DynamicStruct userOpStruct = createTransactionUserOp(accountAddress,
                transactionParams.getCoin(),
                transactionParams.getFromAddress(),
                transactionParams.getToAddress(),
                transactionParams.getAmount(),
                transactionParams.getData(),
                credentials.getPublicKeyCose());
        String transactionHash = ethUtils.sendContract(wallet,
                ERC4337Const.ENTRYPOINT_ADDRESS,
                ERC4337Const.HANDLE_USEROPERATION,
                Arrays.asList(new DynamicArray(DynamicStruct.class, userOpStruct), new Address(wallet.getAddress())),
                Collections.emptyList());
        System.out.println(transactionHash);
        return transactionHash;
    }

    private DynamicStruct createTransactionUserOp(String accountAddress,
                                                  int coin,
                                                  String fromAddress,
                                                  String toAddress,
                                                  BigDecimal amount,
                                                  String data,
                                                  byte[] fidoPublicKey) throws IOException {
        UserOperation userOperation = new UserOperation();
        userOperation.setAddress(accountAddress);
        BigInteger nonce = getAccountNonce(accountAddress);
        userOperation.setNonce(nonce);
//        byte[] callData = createCalldata(coin, fromAddress, toAddress, amount);
//        userOperation.setCallData(callData);
        userOperation.setL1TxData(createL1TxData(5, coin, fromAddress,toAddress, amount, data));
        userOperation.setCallGasLimit(new BigInteger("300000"));
        userOperation.setVerificationGasLimit(new BigInteger("300000"));
        userOperation.setPreVerificationGas(new BigInteger("21000"));
        userOperation.setMaxFeePerGas(new BigInteger("1000000050"));
        userOperation.setMaxPriorityFeePerGas(new BigInteger("1000000000"));
        userOperation.setFidoPublickey(fidoPublicKey);
        return createUserOpStruct(userOperation);
    }

    private byte[] createCalldata(int coin, String fromAddress, String toAddress, BigDecimal amount) {
        if(coin == ERC20Const.COIN_MAIN){
            return createMainCoinTransferCallData(fromAddress, toAddress, amount);
        }
        String tokenAddress = getTokenAddress(coin);

        return createTokenTransferCallData(tokenAddress,
                BigInteger.ZERO,
                toAddress,
                Convert.toWei(amount, Convert.Unit.ETHER).toBigInteger());
    }

    private byte[] createMainCoinTransferCallData(String fromAddress, String toAddress, BigDecimal amount) {
        BigDecimal value = Convert.toWei(amount, Convert.Unit.ETHER);
        Function callData = new Function(
                "L1transfer",
                Arrays.asList(new Uint64(5), new Address(fromAddress), new Address(toAddress), new Uint256(value.longValue()), DynamicBytes.DEFAULT),
                Collections.emptyList()
        );
//        System.out.println(FunctionEncoder.encode(callData));
        byte[] callDataBytes = Numeric.hexStringToByteArray(FunctionEncoder.encode(callData));
        return callDataBytes;
    }

    private String getTokenAddress(int coin) {
        if(coin == ERC20Const.COIN_DEMO){
            return ERC20Const.COIN_DEMO_ADDRESS;
        }
        return null;
    }

    //TODO:public2private
    public BigInteger getAccountNonce(String accountAddress) throws IOException {
        List<Type> typeList = ethUtils.ethCall(ERC4337Const.ENTRYPOINT_ADDRESS,
                ERC4337Const.GET_NONCE,
                Arrays.asList(new Address(accountAddress), new Uint192(0)),
                List.of(new TypeReference<Uint256>() {
                }));
        return ((Uint256) typeList.get(0)).getValue();
    }

    private String findAccountContractOnChain(byte[] publicKeyCose) {
        return null;
    }

    public byte[] createTokenTransferCallData(String tokenAddr,
                                                    BigInteger value,
                                                    String toAddress,
                                                    BigInteger amount){
        Function tokenTransfer = new Function(
                ERC20Const.transfer,
                Arrays.asList(new Address(toAddress), new Uint256(amount)),
                List.of(new TypeReference<Bool>() {})
        );
        byte[] tokenTransferBytes = Numeric.hexStringToByteArray(FunctionEncoder.encode(tokenTransfer));

        //创建UserOp的calldata
        Function callData = new Function(
                ERC4337Const.EXECUTE,
                Arrays.asList(new Address(tokenAddr), new Uint256(value), new DynamicBytes(tokenTransferBytes)),
                Collections.emptyList()
        );
        byte[] callDataBytes = Numeric.hexStringToByteArray(FunctionEncoder.encode(callData));

        return callDataBytes;

    }

    public byte[] createInitCode(byte[] fidoPublicKey, int salt) throws IOException {
        byte[] walletOwnerBytes = Numeric.hexStringToByteArray(ERC4337Const.FACTORY_ADDRESS.replace("0x", ""));
        Function deployWallet = new Function(
                ERC4337Const.DEPLOY_WALLET,
                Arrays.asList(new DynamicBytes(fidoPublicKey), new Uint256(salt)),
                Collections.emptyList()
        );
        byte[] deployWalletBytes = Numeric.hexStringToByteArray((FunctionEncoder.encode(deployWallet)));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(walletOwnerBytes);
        outputStream.write(deployWalletBytes);
        return outputStream.toByteArray();
    }

    public byte[] createPaymasterAndData() throws IOException {
        byte[] aaasCreationPaymasterBytes = Numeric.hexStringToByteArray(ERC4337Const.AAAS_CREATION_PAYMASTER_ADDRESS.replace("0x", ""));
        long MOCK_VALID_UNTIL = System.currentTimeMillis()/1000;
        long MOCK_VALID_AFTER = MOCK_VALID_UNTIL + 10000; //有效期三分钟
        String validTimeStr = DefaultFunctionEncoder.encodeConstructor(Arrays.asList(new Uint48(MOCK_VALID_AFTER), new Uint48(MOCK_VALID_UNTIL)));
        byte[] validTimeBytes = Numeric.hexStringToByteArray(validTimeStr);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(aaasCreationPaymasterBytes);
        outputStream.write(validTimeBytes);
        System.out.println(Numeric.toHexString(outputStream.toByteArray()));
        return outputStream.toByteArray();
    }

    //public2private
    public byte[] createL1TxData(int chainId, int coin, String fromAddress, String toAddress, BigDecimal amount, String data){
        if(coin == ERC20Const.COIN_MAIN){
            return createMainCoinL1TxData(chainId, fromAddress, toAddress, amount, data);
        }
        return null;
    }

    private byte[] createMainCoinL1TxData(int chainId, String fromAddress, String toAddress, BigDecimal amount, String data) {
        String l1TxDataStr = FunctionEncoder.encodeConstructor(Arrays.asList(
                new Uint64(chainId),
                new Address(fromAddress),
                new Address(toAddress),
                new Uint256(Convert.toWei(amount, Convert.Unit.ETHER).toBigInteger()),
                new DynamicBytes(Numeric.hexStringToByteArray(data))
        ));
        return Numeric.hexStringToByteArray(l1TxDataStr);
    }

    public void registerSoulAccount(Wallet wallet, byte[] publicKeyCose) throws IOException {
        String accountAddress = createSoulAccount(publicKeyCose, ERC4337Const.ACCOUNT_SALT);
        //账户打钱
        CompletableFuture<List<String>> txFuture = CompletableFuture.supplyAsync(()-> ethUtils.sendGasFee(wallet.getAddress(), accountAddress));
        CompletableFuture.allOf(txFuture).thenRun(()->{
            String tx1Hash = txFuture.join().get(0);
            String tx2Hash = txFuture.join().get(1);
            System.out.println(tx1Hash);
            System.out.println(tx2Hash);
            CompletableFuture<Void> confirmTxFuture = CompletableFuture.runAsync(() -> {
                try {
                    ethUtils.confirmTransaction(tx1Hash, tx2Hash);
                } catch (InterruptedException e) {
                    //确认交易超时了
                    log.error("user" + wallet.getAppUserId() + "注册时确认交易超时");
                    throw new RuntimeException(e);
                }
            });
            try {
                Thread.sleep(5000L);
            } catch (InterruptedException e) {
            }
            CompletableFuture.allOf(confirmTxFuture).thenRun(()->{
                String registerHash = null;
                try {
                    DynamicStruct registerUserOp = createRegisterUserOp(accountAddress, publicKeyCose);
                    registerHash = ethUtils.sendContract(wallet,
                            ERC4337Const.ENTRYPOINT_ADDRESS,
                            ERC4337Const.HANDLE_USEROPERATION,
                            Arrays.asList(new DynamicArray(DynamicStruct.class, registerUserOp), new Address(wallet.getAddress())),
                            Collections.emptyList());
                } catch (Exception e) {
                    System.out.println("注册SoulAccount失败:" + e.getMessage());
                    throw new TransactionFailedException("注册SoulAccount失败");
                }
                web3j.ethGetTransactionReceipt(registerHash).sendAsync().thenRun(()->{
                    wallet.setContractAddress(accountAddress);
                    walletRepo.save(wallet);
                });
                System.out.println("注册hash：" + registerHash);
            });
        });
    }

    public DynamicStruct createRegisterUserOp(String accountAddress, byte[] publicKeyCose) throws IOException {
        UserOperation userOperation = new UserOperation();

//        int salt = (int) (System.currentTimeMillis()/1000);
        userOperation.setAddress(accountAddress);
        userOperation.setFidoPublickey(publicKeyCose);
        byte[] initCode = createInitCode(publicKeyCose, ERC4337Const.ACCOUNT_SALT);
        System.out.println(Numeric.toHexString(initCode));
        userOperation.setInitCode(initCode);
        userOperation.setVerificationGasLimit(new BigInteger("1500000"));
        userOperation.setPreVerificationGas(new BigInteger("21000"));
        userOperation.setMaxFeePerGas(new BigInteger("1000000050"));
        userOperation.setMaxPriorityFeePerGas(new BigInteger("1000000000"));
        userOperation.setPaymasterAndData(createPaymasterAndData());

        //获取userOp签名
//        byte[] userOpSignature = createUserOpSignature(wallet, userOperation);
//        userOperation.setSignature(userOpSignature);

        return createUserOpStruct(userOperation);
    }

    public String createSoulAccount(byte[] publicKeyCose) throws IOException {
        return createSoulAccount(publicKeyCose, ERC4337Const.ACCOUNT_SALT);
    }

    public String createSoulAccount(byte[] publicKeyCose, int salt) throws IOException {
        List<Type> typeList = ethUtils.ethCall(ERC4337Const.FACTORY_ADDRESS,
                ERC4337Const.DEPLOY_WALLET,
                Arrays.asList(new DynamicBytes(publicKeyCose),
                        new Uint256(salt)),
                List.of(new TypeReference<Address>() {
                })
        );
        if(typeList.size() == 0){
            throw new UserRegisterFailException("用户注册SoulAccount失败");
        }
        return typeList.get(0).toString();
    }

    private byte[] createUserOpSignature(Wallet wallet, UserOperation userOperation) throws IOException {
        DynamicStruct userOpStruct = createUserOpStruct(userOperation);
        List<Type> results = ethUtils.ethCall(ERC4337Const.ENTRYPOINT_ADDRESS,
                ERC4337Const.GET_USEROPERATION_HASH,
                List.of(userOpStruct),
                List.of(new TypeReference<Bytes32>() {}));
        if(results.size() == 0){
            throw new EthCallException("获取UserOperation的hash值失败");
        }
        byte[] userOpHash = ((Bytes32) results.get(0)).getValue();
        Credentials credentials = Credentials.create(AESUtils.decrypt(wallet.getPrivateKey()));
        ECKeyPair keyPair = credentials.getEcKeyPair();

        Sign.SignatureData signature = Sign.signMessage(userOpHash, keyPair);
        // 将对象的三个属性拼接为一个byte数组
        byte[] signatureBytes = new byte[65];
        System.arraycopy(signature.getR(), 0, signatureBytes, 0, 32);
        System.arraycopy(signature.getS(), 0, signatureBytes, 32, 32);
        System.arraycopy(signature.getV(), 0, signatureBytes, 64, 1);
        return signatureBytes;
    }
}
