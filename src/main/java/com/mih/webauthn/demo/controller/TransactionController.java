package com.mih.webauthn.demo.controller;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mih.webauthn.demo.constant.BlockchainConst;
import com.mih.webauthn.demo.controller.response.CommonPage;
import com.mih.webauthn.demo.controller.response.CommonResult;
import com.mih.webauthn.demo.domain.Transaction;
import com.mih.webauthn.demo.domain.TransactionRepo;
import com.mih.webauthn.demo.domain.Wallet;
import com.mih.webauthn.demo.domain.WalletRepo;
import com.mih.webauthn.demo.domain.vo.TransactionDetails;
import com.mih.webauthn.demo.domain.vo.TransactionParams;
import com.mih.webauthn.demo.exception.TransactionFailedException;
import com.mih.webauthn.demo.service.TransactionService;
import com.mih.webauthn.demo.utils.ERC4337Utils;
import com.mih.webauthn.demo.utils.EthUtils;
import com.mih.webauthn.demo.utils.ServletUtils;
import com.mih.webauthn.demo.utils.UserDetailsUtils;
import com.yubico.webauthn.RelyingParty;
import io.github.webauthn.config.InMemoryOperation;
import io.github.webauthn.config.WebAuthnOperation;
import io.github.webauthn.domain.WebAuthnCredentialsRepository;
import io.github.webauthn.domain.WebAuthnUserRepository;
import io.github.webauthn.dto.AssertionFinishRequest;
import io.github.webauthn.dto.AssertionStartRequest;
import io.github.webauthn.dto.AssertionStartResponse;
import io.github.webauthn.flows.WebAuthnAssertionFinishStrategy;
import io.github.webauthn.flows.WebAuthnAssertionStartStrategy;
import io.github.webauthn.jpa.JpaWebAuthnCredentials;
import io.github.webauthn.jpa.JpaWebAuthnUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Numeric;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("api/transaction")
@CrossOrigin(origins = {"http://localhost:8000", "http://localhost:3000", "https://asn.aspark.space"}, allowCredentials = "true")
public class TransactionController {
    private static final Logger log = LoggerFactory.getLogger(TransactionController.class);

    @Autowired
    private ObjectMapper mapper ;

    @Autowired
    private ServletUtils servletUtils;

    @Autowired
    private UserDetailsUtils userDetailsUtils;

    @Autowired
    private RelyingParty relyingParty;

    @Autowired
    private Web3j web3j;

    private final WebAuthnOperation<AssertionStartResponse, String> operation = new InMemoryOperation<>();

    @Autowired
    private WebAuthnUserRepository<JpaWebAuthnUser> webAuthnUserRepository;

    @Autowired
    private WebAuthnCredentialsRepository<JpaWebAuthnCredentials> webAuthnCredentialsRepository;

    @Autowired
    private WalletRepo walletRepo;

    @Autowired
    private ConcurrentMapCache cacheMap;

    @Autowired
    private ERC4337Utils erc4337Utils;

    @Autowired
    private TransactionRepo transactionRepo;

    @Autowired
    private TransactionService transactionService;


    @RequestMapping(value = "start", method = RequestMethod.POST)
    public void signRequest(@RequestBody TransactionParams params,
                            HttpServletResponse response) throws IOException {
        //TODO:校验请求参数是否合法
        //TODO:选择哪一条链下去发送交易
        //TODO:防止用户点快了多发送了一笔交易
        //TODO:发送交易前确保用户余额足够

        // 获取登录用户的信息
        UserDetails user = userDetailsUtils.getUserDetails();

        if(user == null){
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "用户尚未登录"));
            return;
        }

        JpaWebAuthnUser userEntity = webAuthnUserRepository.findByUsername(user.getUsername()).get();


        if(!transactionService.verifyFromAddress(params.getFromAddress(), userEntity.getId())){
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "fromAddress有误"));
        }
        AssertionStartRequest startRequest = new AssertionStartRequest();
        startRequest.setUsername(user.getUsername());
        WebAuthnAssertionStartStrategy assertionStartStrategy = new WebAuthnAssertionStartStrategy(relyingParty, operation);
        try {
            AssertionStartResponse start = assertionStartStrategy.start(startRequest);
            String json = mapper.writeValueAsString(start);
            JSONObject assertionStartResponse = JSONObject.parseObject(json);
            assertionStartResponse.put("requestParams", params);
            servletUtils.writeToResponse(response, assertionStartResponse.toJSONString());

            cacheMap.put(start.getAssertionId(), params);
        } catch (UsernameNotFoundException e) {
            servletUtils.writeBadRequestToResponse(response, Map.of("message", e.getMessage()));
        }
    }

    @RequestMapping("finish")
    public Object signResponse(HttpServletRequest request) throws IOException{
        // 获取登录用户的信息
        UserDetails user = userDetailsUtils.getUserDetails();

        if(user == null){
            return CommonResult.unAuthorization();
        }
        JpaWebAuthnUser userEntity = webAuthnUserRepository.findByUsername(user.getUsername()).get();
        WebAuthnAssertionFinishStrategy assertionFinishStrategy = new WebAuthnAssertionFinishStrategy(
                webAuthnUserRepository,
                webAuthnCredentialsRepository,
                relyingParty,
                operation);
        AssertionFinishRequest body = servletUtils.parseRequest(request, AssertionFinishRequest.class);
        Optional<WebAuthnAssertionFinishStrategy.AssertionSuccessResponse> res = null;
        try {
            res = assertionFinishStrategy.finish(body);
        } catch (Exception e) {
            return CommonResult.failed(e.getMessage());
        }
        if (res.isEmpty()) {
            return CommonResult.failed("验证签名失败");
        }

//        Iterator<Wallet> walletIterator = walletRepo.findByAppUserId(userEntity.getId()).iterator();
//        if(!walletIterator.hasNext()){
//            servletUtils.writeBadRequestToResponse(response, Map.of("message", "用户尚未导入区块链私钥"));
//            return null;
//        }

        Wallet wallet = walletRepo.findByAppUserId(userEntity.getId()).iterator().next();
        TransactionParams requestParams = cacheMap.get(body.getAssertionId(), TransactionParams.class);

        String transactionHash = null;
        try {
            transactionHash = erc4337Utils.sendTransaction(wallet, requestParams, body.getCredential().getId().getBytes());
        } catch (TransactionFailedException e) {
            return CommonResult.failed(e.getMessage());
        }
        //TODO:处理发送交易后可能会发生的报错
        Long l1AddressId = transactionService.findL1AddressIdByAddress(requestParams.getFromAddress());
        Transaction transaction = new Transaction(userEntity.getId(), "5", requestParams.getCoin(), l1AddressId, requestParams.getToAddress(),
                requestParams.getAmount(), transactionHash);
        transactionRepo.save(transaction);

        cacheMap.evict(body.getAssertionId());
        return CommonResult.success(Map.of("transactionHash", transactionHash));
    }

    @RequestMapping("list")
    public CommonResult<CommonPage<Transaction>> queryTransactionList(@RequestParam(defaultValue = "1") Integer pageNum,
                                                                      @RequestParam(defaultValue = "20") Integer pageSize){
        UserDetails user = userDetailsUtils.getUserDetails();

        if(user == null){
            return CommonResult.unAuthorization();
        }
        JpaWebAuthnUser userEntity = webAuthnUserRepository.findByUsername(user.getUsername()).get();
        List<Transaction> transactionList = transactionService.findAllByAppUserId(userEntity.getId(), 1, 20);
        return CommonResult.success(CommonPage.restPage(transactionList));
    }

    @RequestMapping("queryOneTransaction")
    public CommonResult<TransactionDetails> queryOneTransaction(@RequestParam Integer transactionId){
        UserDetails user = userDetailsUtils.getUserDetails();
        if(user == null){
            return CommonResult.unAuthorization();
        }
        if (transactionRepo.findById(transactionId).isEmpty()) {
            return CommonResult.failed("交易id有误");
        }
        JpaWebAuthnUser userEntity = webAuthnUserRepository.findByUsername(user.getUsername()).get();
        Transaction transactionEntity = transactionRepo.findById(transactionId).get();
        if (!transactionEntity.getAppUserId().equals(userEntity.getId())){
            return CommonResult.failed("交易id有误");
        }
        TransactionDetails transactionDetails = transactionService.getTransactionDetailsById(transactionId);
        return CommonResult.success(transactionDetails);
    }

    @RequestMapping("test")
    public String test(@RequestParam String from, @RequestParam String to) throws IOException {
        BigInteger gas = new BigInteger("21000");
        BigInteger gasPrice = new BigInteger("14300000000");
        BigInteger value = BigInteger.ZERO;
        BigInteger nonce = web3j.ethGetTransactionCount(from, DefaultBlockParameterName.LATEST).send().getTransactionCount();
        // 构造交易
        // 创建一个转账交易对象并签名
        RawTransaction rawTransaction = RawTransaction.createEtherTransaction(5L, nonce, gas, to, value, BigInteger.ZERO, gasPrice);
        Credentials credential = Credentials.create("5b0dc78a4a58f97795443ac935851d38dea4ab9ad48e61678f61d58ca71ace7d");
        System.out.println(credential.getAddress());
        byte[] signMessage = TransactionEncoder.signMessage(rawTransaction, credential);
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(Numeric.toHexString(signMessage)).send();
        return ethSendTransaction.getTransactionHash();
    }

    @RequestMapping("test2")
    public String test2(@RequestParam String hash) throws IOException {
        org.web3j.protocol.core.methods.response.Transaction transaction = web3j.ethGetTransactionByHash(hash).send().getTransaction().get();
        return transaction.toString();
    }

}
