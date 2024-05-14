package com.mih.webauthn.demo.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mih.webauthn.demo.controller.response.CommonResult;
import com.mih.webauthn.demo.domain.vo.DeleteCredentialParams;
import com.mih.webauthn.demo.domain.vo.TransactionParams;
import com.mih.webauthn.demo.service.CredentialService;
import com.mih.webauthn.demo.utils.CommonUtils;
import com.mih.webauthn.demo.utils.ServletUtils;
import com.mih.webauthn.demo.utils.UserDetailsUtils;
import com.yubico.webauthn.RelyingParty;
import io.github.webauthn.config.InMemoryOperation;
import io.github.webauthn.config.WebAuthnOperation;
import io.github.webauthn.config.WebAuthnUsernameAuthenticationToken;
import io.github.webauthn.domain.*;
import io.github.webauthn.dto.*;
import io.github.webauthn.flows.*;
import io.github.webauthn.jpa.JpaWebAuthnCredentials;
import io.github.webauthn.jpa.JpaWebAuthnUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;
import org.springframework.web.bind.annotation.*;
import org.web3j.utils.Numeric;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

import static java.util.Optional.empty;
import static java.util.Optional.ofNullable;

@RestController
@RequestMapping("api/credential")
@CrossOrigin(origins = "http://localhost:30000", allowCredentials = "true")
public class CredentialController {
    private static final Logger log = LoggerFactory.getLogger(CredentialController.class);

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private ServletUtils servletUtils;

    @Autowired
    private ObjectMapper mapper ;

    @Autowired
    private UserDetailsUtils userDetailsUtils;

    @Autowired
    private WebAuthnUserRepository<JpaWebAuthnUser> webAuthnUserRepository;

    @Autowired
    private WebAuthnCredentialsRepository<JpaWebAuthnCredentials> webAuthnCredentialsRepository;

    @Autowired
    private RelyingParty relyingParty;

    @Autowired
    private WebAuthnOperation<RegistrationStartResponse, String> registrationOperation;

    @Autowired
    private ConcurrentMapCache cacheMap;

    private WebAuthnRegistrationStartStrategy registerStartStrategy;

    private WebAuthnRegistrationFinishStrategy registerFinishStrategy;

    private WebAuthnAssertionStartStrategy assertionStartStrategy;

    private WebAuthnAssertionFinishStrategy assertionFinishStrategy;

    private final WebAuthnOperation<AssertionStartResponse, String> assertionOperation = new InMemoryOperation<>();

    private Supplier<WebAuthnUser> userSupplier = () -> {
        AbstractAuthenticationToken token = null;
        if(SecurityContextHolder.getContext().getAuthentication() instanceof UsernamePasswordAuthenticationToken){
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

    private final BiConsumer<WebAuthnUser, WebAuthnCredentials> successHandler = (user, credentials) -> {
        UsernamePasswordAuthenticationToken token = new WebAuthnUsernameAuthenticationToken(user, credentials, Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(token);
    };

    @PostConstruct
    public void init() {
        this.registerStartStrategy = new WebAuthnRegistrationStartStrategy(webAuthnUserRepository,
                webAuthnCredentialsRepository,
                relyingParty,
                registrationOperation);
        this.registerFinishStrategy = new WebAuthnRegistrationFinishStrategy(webAuthnUserRepository,
                webAuthnCredentialsRepository,
                relyingParty,
                registrationOperation);
        this.assertionStartStrategy = new WebAuthnAssertionStartStrategy(relyingParty, assertionOperation);
        this.assertionFinishStrategy = new WebAuthnAssertionFinishStrategy(webAuthnUserRepository, webAuthnCredentialsRepository, relyingParty, assertionOperation);
    }

    @RequestMapping("list")
    public CommonResult queryCredentials(){
        // 获取登录用户的信息
        UserDetails user = userDetailsUtils.getUserDetails();
        if(user == null){
            return CommonResult.unAuthorization();
        }
        WebAuthnUser userEntity = (WebAuthnUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<String> credentialList = credentialService.findAllByAppUserId(userEntity.getId());
        return CommonResult.success(credentialList);
    }

//    @RequestMapping("delete")
//    public CommonResult deleteCredential(@AuthenticationPrincipal UserDetails user, @RequestParam String fidoId) throws IOException {
//        if(user == null){
//            return CommonResult.unAuthorization();
//        }
//        WebAuthnUser userEntity = (WebAuthnUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//        WebAuthnCredentials credential = (WebAuthnCredentials) SecurityContextHolder.getContext().getAuthentication().getCredentials();
//        if(fidoId.equals(Numeric.toHexString(credential.getPublicKeyCose()))) {
//            return CommonResult.failed("无法删除当前登录设备");
//        }
//        credentialService.deleteCredential(userEntity.getId(), fidoId);
//        return CommonResult.success();
//    }

    @RequestMapping(value = "delete/start", method = RequestMethod.POST)
    public void loginStart(@RequestBody DeleteCredentialParams params,
                           HttpServletResponse response) throws IOException {
        // 获取登录用户的信息
        UserDetails user = userDetailsUtils.getUserDetails();
        if(user == null){
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "用户尚未登录"));
            return;
        }
        AssertionStartRequest startRequest = new AssertionStartRequest();
        startRequest.setUsername(user.getUsername());

        try {
            AssertionStartResponse start = this.assertionStartStrategy.start(startRequest);
            String json = this.mapper.writeValueAsString(start);
            servletUtils.writeToResponse(response, json);
            cacheMap.put(start.getAssertionId(), params);
        } catch (UsernameNotFoundException var9) {
            servletUtils.writeBadRequestToResponse(response, Map.of("message", var9.getMessage()));
        }
    }

    @RequestMapping("delete/finish")
    public CommonResult loginFinish(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 获取登录用户的信息
        UserDetails user = userDetailsUtils.getUserDetails();

        if(user == null){
            return CommonResult.unAuthorization();
        }
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
        String fidoId = cacheMap.get(body.getAssertionId(), DeleteCredentialParams.class).getFidoId();
        WebAuthnUser userEntity = (WebAuthnUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        WebAuthnCredentials credential = (WebAuthnCredentials) SecurityContextHolder.getContext().getAuthentication().getCredentials();
        if(fidoId.equals(Numeric.toHexString(credential.getPublicKeyCose()))) {
            return CommonResult.failed("无法删除当前登录设备");
        }
        credentialService.deleteCredential(userEntity.getId(), fidoId);
        return CommonResult.success();
    }

    @RequestMapping(value = "register/start", method = RequestMethod.POST)
    public void registerStart(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 获取登录用户的信息
        UserDetails user = userDetailsUtils.getUserDetails();

        if(user == null){
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "用户尚未登录"));
            return;
        }
        RegistrationStartRequest body = new RegistrationStartRequest();
        try {
            Optional<WebAuthnUser> currentUser = userSupplier != null ? ofNullable(userSupplier.get()) : empty();
            RegistrationStartResponse registrationStartResponse = registerStartStrategy.registrationStart(body, currentUser);
            //String json = mapper.writeValueAsString(registrationStartResponse);
            String json = mapper.writeValueAsString(registrationStartResponse).replace("\"id\":\"localhost\",", "");

            servletUtils.writeToResponse(response, json);
        }  catch (UsernameAlreadyExistsException var10) {
            //servletUtils.writeBadRequestToResponse(response, new RegistrationStartResponse(RegistrationStartResponse.Status.USERNAME_TAKEN));
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "The username already exists!"));
        } catch (InvalidTokenException var11) {
            //servletUtils.writeBadRequestToResponse(response, new RegistrationStartResponse(RegistrationStartResponse.Status.TOKEN_INVALID));
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "无效的token！"));
        }
    }

    @RequestMapping(value = "register/finish", method = RequestMethod.POST)
    @Transactional
    public void registerFinish(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            RegistrationFinishRequest body = (RegistrationFinishRequest)servletUtils.parseRequest(request, RegistrationFinishRequest.class);
            Map<String, String> map = registerFinishStrategy.registrationFinish(body);
            String json = this.mapper.writeValueAsString(map);
            servletUtils.writeToResponse(response, json);
        } catch (Exception e) {
            log.error("注册失败：" + e.getMessage());
            log.error(CommonUtils.toStackTrace(e));
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
            servletUtils.writeBadRequestToResponse(response, Map.of("message", "注册失败，请联系管理员。"));
        }

    }
}
