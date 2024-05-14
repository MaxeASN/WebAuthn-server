package com.mih.webauthn.demo.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mih.webauthn.demo.domain.Wallet;
import com.mih.webauthn.demo.domain.dto.L1RpcParams;
import com.mih.webauthn.demo.domain.dto.L1RpcResponse;
import com.mih.webauthn.demo.domain.vo.RegisterParams;
import com.mih.webauthn.demo.exception.UserRegisterFailException;
import com.mih.webauthn.demo.service.FaceDataService;
import com.mih.webauthn.demo.service.FidoService;
import com.mih.webauthn.demo.service.L1RpcService;
import com.mih.webauthn.demo.utils.AESUtils;
import com.mih.webauthn.demo.utils.CommonUtils;
import com.mih.webauthn.demo.utils.ERC4337Utils;
import com.mih.webauthn.demo.utils.ServletUtils;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import io.github.webauthn.BytesUtil;
import io.github.webauthn.config.WebAuthnOperation;
import io.github.webauthn.domain.WebAuthnCredentialsRepository;
import io.github.webauthn.domain.WebAuthnUser;
import io.github.webauthn.domain.WebAuthnUserRepository;
import io.github.webauthn.dto.RegistrationFinishRequest;
import io.github.webauthn.dto.RegistrationStartRequest;
import io.github.webauthn.dto.RegistrationStartResponse;
import io.github.webauthn.flows.InvalidTokenException;
import io.github.webauthn.flows.UsernameAlreadyExistsException;
import io.github.webauthn.flows.WebAuthnRegistrationFinishStrategy;
import io.github.webauthn.flows.WebAuthnRegistrationStartStrategy;
import io.github.webauthn.jpa.JpaWebAuthnCredentials;
import io.github.webauthn.jpa.JpaWebAuthnUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static java.util.Optional.empty;
import static java.util.Optional.ofNullable;

@RestController
@RequestMapping("api/diyRegister")
@CrossOrigin(origins = {"http://localhost:8000", "http://localhost:3000", "https://asn.aspark.space","chrome-extension://eibjaipogpeejolfbfkmcinienpihmnb"}, allowCredentials = "true")

public class RegisterController {
    private static final Logger log = LoggerFactory.getLogger(RegisterController.class);

    @Autowired
    private ServletUtils servletUtils;

    @Autowired
    private ObjectMapper mapper ;

    @Autowired
    private WebAuthnUserRepository<JpaWebAuthnUser> webAuthnUserRepository;

    @Autowired
    private WebAuthnCredentialsRepository<JpaWebAuthnCredentials> webAuthnCredentialsRepository;

    @Autowired
    private RelyingParty relyingParty;

    @Autowired
    private WebAuthnOperation<RegistrationStartResponse, String> registrationOperation;

    @Autowired
    private ERC4337Utils erc4337Utils;

    @Autowired
    private FidoService fidoService;

    private WebAuthnRegistrationStartStrategy startStrategy;

    private WebAuthnRegistrationFinishStrategy finishStrategy;

    @Autowired
    private ConcurrentMapCache cacheMap;

    @Autowired
    private FaceDataService faceDataService;

    @Autowired
    @Qualifier("l1RpcService")
    private L1RpcService l1RpcService;

    private Supplier<WebAuthnUser> userSupplier = () -> {
        AbstractAuthenticationToken token = null;
        if(SecurityContextHolder.getContext().getAuthentication() instanceof  UsernamePasswordAuthenticationToken){
            token = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        }else if(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken){
            token = (AnonymousAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        }
        if (token == null)
            return null;

        Object principal = token.getPrincipal();
        if (principal instanceof WebAuthnUser) {
            return (WebAuthnUser) principal;
        } else {
            log.warn("userSupplier - you need to configure your WebAuthnConfigurer.userSupplier method to tranform your principal implementation to something that webauthn starter can understand");
        }
        return null;
    };

    @PostConstruct
    public void init() {
        this.startStrategy = new WebAuthnRegistrationStartStrategy(webAuthnUserRepository,
                webAuthnCredentialsRepository,
                relyingParty,
                registrationOperation);
        this.finishStrategy = new WebAuthnRegistrationFinishStrategy(webAuthnUserRepository,
                webAuthnCredentialsRepository,
                relyingParty,
                registrationOperation);
    }

    @RequestMapping("start")  //@RequestBody RegisterParams registerParams,   , @AuthenticationPrincipal UserDetails user
    public void registerStart(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //TODO:当用户登录成功后，再去注册时会将设备注册进登录的账户下
//        if(user != null){
//            servletUtils.writeBadRequestToResponse(response, Map.of("message", "Please log out before re registering!"));
//            return;
//        }
    //        String faceData = registerParams.getFaceData();
    //        if(!StringUtils.hasText(faceData) || !CommonUtils.isFaceData(faceData)){
    //            servletUtils.writeBadRequestToResponse(response, Map.of("message", "RequestParams error"));
    //            return;
    //        }
        RegistrationStartRequest body = servletUtils.parseRequest(request, RegistrationStartRequest.class);
//        RegistrationStartRequest body = servletUtils.parseRegisterParams(registerParams);
        try {
            Optional<WebAuthnUser> currentUser = userSupplier != null ? ofNullable(userSupplier.get()) : empty();
            currentUser = empty();
            RegistrationStartResponse registrationStartResponse = startStrategy.registrationStart(body, currentUser);

            //String json = mapper.writeValueAsString(registrationStartResponse);
            String json = mapper.writeValueAsString(registrationStartResponse).replace("\"id\":\"localhost\",", "");
//            ByteArray id = UserIdentity.builder().name("122").displayName("122").id(new ByteArray(BytesUtil.longToBytes(121L))).build().getId();
//            json = mapper.writeValueAsString(id);
            servletUtils.writeToResponse(response, json);
//            cacheMap.put(registrationStartResponse.getRegistrationId(), registerParams);
        }  catch (UsernameAlreadyExistsException var10) {
            //servletUtils.writeBadRequestToResponse(response, new RegistrationStartResponse(RegistrationStartResponse.Status.USERNAME_TAKEN));
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "The username already exists!"));
        } catch (InvalidTokenException var11) {
            //servletUtils.writeBadRequestToResponse(response, new RegistrationStartResponse(RegistrationStartResponse.Status.TOKEN_INVALID));
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "无效的token！"));
        }
    }

    @RequestMapping("finish")
    @Transactional
    public void registerFinish(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String registrationId = "";
        try {
            RegistrationFinishRequest body = (RegistrationFinishRequest)servletUtils.parseRequest(request, RegistrationFinishRequest.class);
            Map<String, String> map = finishStrategy.registrationFinish(body);
            String json = this.mapper.writeValueAsString(map);
            registrationId = body.getRegistrationId();
            //给用户生成一个以太坊私钥,并导出地址存进数据库
            byte[] credentialId = body.getCredential().getId().getBytes();
            JpaWebAuthnCredentials credential = webAuthnCredentialsRepository.findByCredentialId(credentialId).get(0);
            Wallet wallet = fidoService.registerAddressAndPrivateKey(credential.getAppUserId());
            //导入人脸数据
//            String faceData = cacheMap.get(body.getRegistrationId(), RegisterParams.class).getFaceData();
//            faceDataService.importFaceDate(credential.getAppUserId(), faceData);
            //向我们的链注册
            fidoService.registerL1Address(credential.getAppUserId(), wallet.getAddress());

//            L1RpcResponse l1RpcResponse = l1RpcService.importRawKey(L1RpcParams.importRawKeyParams(1, AESUtils.decrypt(wallet.getPrivateKey())));
//            if(l1RpcResponse.getError() != null){
//                throw new UserRegisterFailException("通过rpc请求导入私钥失败");
//            }
            //调合约注册
            erc4337Utils.registerSoulAccount(wallet, credential.getPublicKeyCose());

            servletUtils.writeToResponse(response, json);
        } catch (Exception e) {
            log.error("注册失败：" + e.getMessage());
            log.error(CommonUtils.toStackTrace(e));
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "注册失败，请联系管理员。"));
        } finally {
            cacheMap.evict(registrationId);
        }

    }


    @RequestMapping("add_start")  //@RequestBody RegisterParams registerParams,   , @AuthenticationPrincipal UserDetails user
    public void registerAddStart(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //TODO:当用户登录成功后，再去注册时会将设备注册进登录的账户下
        RegistrationStartRequest body = servletUtils.parseRequest(request, RegistrationStartRequest.class);
//        RegistrationStartRequest body = servletUtils.parseRegisterParams(registerParams);
        try {
            Optional<WebAuthnUser> currentUser = userSupplier != null ? ofNullable(userSupplier.get()) : empty();

            RegistrationStartResponse registrationStartResponse = startStrategy.registrationStart(body, currentUser);

            String json = mapper.writeValueAsString(registrationStartResponse).replace("\"id\":\"localhost\",", "");

            servletUtils.writeToResponse(response, json);

        }  catch (UsernameAlreadyExistsException var10) {

            servletUtils.writeBadRequestToResponse(response, Map.of("message", "The username already exists!"));
        } catch (InvalidTokenException var11) {

            servletUtils.writeBadRequestToResponse(response, Map.of("message", "无效的token！"));
        }
    }

    @RequestMapping("add_finish")
    @Transactional
    public void registerAddFinish(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String registrationId = "";
        try {
            RegistrationFinishRequest body = (RegistrationFinishRequest)servletUtils.parseRequest(request, RegistrationFinishRequest.class);
            Map<String, String> map = finishStrategy.registrationFinish(body);
            String json = this.mapper.writeValueAsString(map);

            servletUtils.writeToResponse(response, json);
        } catch (Exception e) {
            log.error("注册失败：" + e.getMessage());
            log.error(CommonUtils.toStackTrace(e));
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "注册失败，请联系管理员。"));
        } finally {
            cacheMap.evict(registrationId);
        }

    }
}
