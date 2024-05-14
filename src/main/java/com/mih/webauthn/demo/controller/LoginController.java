package com.mih.webauthn.demo.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mih.webauthn.demo.utils.JWTUtils;
import com.mih.webauthn.demo.utils.ServletUtils;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserIdentity;
import io.github.webauthn.BytesUtil;
import io.github.webauthn.config.InMemoryOperation;
import io.github.webauthn.config.WebAuthnOperation;
import io.github.webauthn.config.WebAuthnUsernameAuthenticationToken;
import io.github.webauthn.domain.WebAuthnCredentials;
import io.github.webauthn.domain.WebAuthnCredentialsRepository;
import io.github.webauthn.domain.WebAuthnUser;
import io.github.webauthn.domain.WebAuthnUserRepository;
import io.github.webauthn.dto.AssertionFinishRequest;
import io.github.webauthn.dto.AssertionStartRequest;
import io.github.webauthn.dto.AssertionStartResponse;
import io.github.webauthn.flows.WebAuthnAssertionFinishStrategy;
import io.github.webauthn.flows.WebAuthnAssertionStartStrategy;
import io.github.webauthn.jpa.JpaWebAuthnCredentials;
import io.github.webauthn.jpa.JpaWebAuthnUser;
import io.jsonwebtoken.Claims;
import io.reactivex.internal.operators.observable.ObservableJoin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.BiConsumer;

@RestController
@RequestMapping("api/diyLogin")
@CrossOrigin(origins = {"http://localhost:8000", "http://localhost:3000", "https://asn.aspark.space","chrome-extension://eibjaipogpeejolfbfkmcinienpihmnb"}, allowCredentials = "true")

public class LoginController {

    @Autowired
    private ServletUtils servletUtils;

    @Autowired
    private ObjectMapper mapper ;

    @Autowired
    private RelyingParty relyingParty;

    private static final SecureRandom random = new SecureRandom();

    private final WebAuthnOperation<AssertionStartResponse, String> assertionOperation = new InMemoryOperation<>();

    @Autowired
    private WebAuthnUserRepository<JpaWebAuthnUser> webAuthnUserRepository;

    @Autowired
    private WebAuthnCredentialsRepository<JpaWebAuthnCredentials> webAuthnCredentialsRepository;

    private WebAuthnAssertionStartStrategy assertionStartStrategy;

    private WebAuthnAssertionFinishStrategy assertionFinishStrategy;

    private final BiConsumer<WebAuthnUser, WebAuthnCredentials> successHandler = (user, credentials) -> {
        UsernamePasswordAuthenticationToken token = new WebAuthnUsernameAuthenticationToken(user, credentials, Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(token);
    };

    @PostConstruct
    public void init() {
        this.assertionStartStrategy = new WebAuthnAssertionStartStrategy(relyingParty, assertionOperation);
        this.assertionFinishStrategy = new WebAuthnAssertionFinishStrategy(webAuthnUserRepository, webAuthnCredentialsRepository, relyingParty, assertionOperation);
    }

    private static ByteArray generateChallenge() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }
    @RequestMapping("start")
    public void loginStart(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AssertionStartRequest startRequest = servletUtils.parseRequest(request, AssertionStartRequest.class);
        try {
            AssertionStartResponse start = this.assertionStartStrategy.start(startRequest);
            String json = this.mapper.writeValueAsString(start);
            servletUtils.writeToResponse(response, json);
        } catch (UsernameNotFoundException var9) {
            servletUtils.writeBadRequestToResponse(response, Map.of("message", var9.getMessage()));
        }
    }

    @RequestMapping("start_direct")
    public void loginStartDirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AssertionStartRequest startRequest = servletUtils.parseRequest(request, AssertionStartRequest.class);
        try {
            byte[] assertionId = new byte[16];
            this.random.nextBytes(assertionId);
            String assertionIdBase64 = Base64.getEncoder().encodeToString(assertionId);
            PublicKeyCredentialRequestOptions.PublicKeyCredentialRequestOptionsBuilder publicKeyCredentialRequestOptionsBuilder = PublicKeyCredentialRequestOptions.builder()
                    .challenge(generateChallenge())
                    .rpId(relyingParty.getIdentity().getId())
                    .allowCredentials(new ArrayList())
                    .extensions(StartAssertionOptions.builder().build().getExtensions().toBuilder().build())
                    .timeout(StartAssertionOptions.builder().build().getTimeout());
            AssertionRequest build = AssertionRequest.builder().publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptionsBuilder.build()).build();
            AssertionStartResponse start = new AssertionStartResponse(assertionIdBase64, build);
            String json = this.mapper.writeValueAsString(start);
            this.assertionOperation.put(start.getAssertionId(), start);
            servletUtils.writeToResponse(response, json);
        } catch (UsernameNotFoundException var9) {
            servletUtils.writeBadRequestToResponse(response, Map.of("message", var9.getMessage()));
        }
    }

    @RequestMapping("finish")
    public void loginFinish(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AssertionFinishRequest body = servletUtils.parseRequest(request, AssertionFinishRequest.class);

        Optional<WebAuthnAssertionFinishStrategy.AssertionSuccessResponse> res = this.assertionFinishStrategy.finish(body);
        res.ifPresent((u) -> {
            this.successHandler.accept(u.getUser(), u.getCredentials());
        });
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", res.get().getUser().getId());
        claims.put("credentials", res.get().getCredentials().getCredentialId());
        claims.put("username", res.get().getUser().getUsername());
        String jwt = JWTUtils.generateJwt(claims);
        Map<String, Object> result = new HashMap<>();
        result.put("username", res.get().getUser().getUsername());
        result.put("jwt", jwt);
//        servletUtils.writeToResponse(response, this.mapper.writeValueAsString(Map.of("username", ((WebAuthnAssertionFinishStrategy.AssertionSuccessResponse)res.get()).getUser().getUsername())));
        servletUtils.writeToResponse(response, this.mapper.writeValueAsString(result));
    }

    @RequestMapping("finish_direct")
    public void loginFinishDirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AssertionFinishRequest body = servletUtils.parseRequest(request, AssertionFinishRequest.class);

        List<JpaWebAuthnCredentials> byCredentialId = webAuthnCredentialsRepository.findByCredentialId(body.getCredential().getId().getBytes());


        Long appUserId = byCredentialId.get(0).getAppUserId();
        Optional<JpaWebAuthnUser> webAuthnUser = webAuthnUserRepository.findById(appUserId);
        String username = webAuthnUser.get().getUsername();
        StartAssertionOptions startAssertionOptions = StartAssertionOptions.builder().username(username).build();
        PublicKeyCredentialRequestOptions.PublicKeyCredentialRequestOptionsBuilder publicKeyCredentialRequestOptionsBuilder = PublicKeyCredentialRequestOptions.builder().challenge(body.getCredential().getResponse().getClientData().getChallenge())
                .rpId(relyingParty.getIdentity().getId()).allowCredentials(new ArrayList(relyingParty.getCredentialRepository().getCredentialIdsForUsername(username)))
                .extensions(startAssertionOptions.getExtensions().toBuilder().build())
                .timeout(startAssertionOptions.getTimeout());
        AssertionRequest assertionRequest = AssertionRequest.builder().publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptionsBuilder.build()).username(username).build();

        AssertionStartResponse response1 = new AssertionStartResponse(body.getAssertionId(), assertionRequest);
        this.assertionOperation.put(body.getAssertionId(), response1);

        Optional<WebAuthnAssertionFinishStrategy.AssertionSuccessResponse> res = this.assertionFinishStrategy.finish(body);
        res.ifPresent((u) -> {
            this.successHandler.accept(u.getUser(), u.getCredentials());
        });

        Map<String, Object> claims = new HashMap<>();
        claims.put("id", res.get().getUser().getId());
        claims.put("credentials", res.get().getCredentials().getCredentialId());
        claims.put("username", res.get().getUser().getUsername());
        String jwt = JWTUtils.generateJwt(claims);
        Map<String, Object> result = new HashMap<>();
        result.put("username", res.get().getUser().getUsername());
        result.put("jwt", jwt);
        Claims claims1 = JWTUtils.parseJWT(jwt);
//        servletUtils.writeToResponse(response, this.mapper.writeValueAsString(Map.of("username", ((WebAuthnAssertionFinishStrategy.AssertionSuccessResponse)res.get()).getUser().getUsername())));
        servletUtils.writeToResponse(response, this.mapper.writeValueAsString(result));
    }
}
