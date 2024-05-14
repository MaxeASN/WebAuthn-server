package com.mih.webauthn.demo;

import com.mih.webauthn.demo.controller.response.CommonResult;
import com.mih.webauthn.demo.domain.Account;
import com.mih.webauthn.demo.domain.AccountRepo;
import com.mih.webauthn.demo.domain.Wallet;
import com.mih.webauthn.demo.domain.WalletRepo;
import io.github.webauthn.domain.WebAuthnCredentials;
import io.github.webauthn.domain.WebAuthnCredentialsRepository;
import io.github.webauthn.domain.WebAuthnUser;
import io.github.webauthn.domain.WebAuthnUserRepository;
import io.github.webauthn.jpa.JpaWebAuthnCredentials;
import io.github.webauthn.jpa.JpaWebAuthnUser;
import org.hibernate.procedure.spi.ParameterRegistrationImplementor;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.web3j.utils.Numeric;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


@Controller
public class HomeController {

    @Autowired
    private WebAuthnUserRepository<JpaWebAuthnUser> webAuthnUserRepository;

    @Autowired
    private WebAuthnCredentialsRepository<JpaWebAuthnCredentials> webAuthnCredentialsRepository;

    @Autowired
    WalletRepo walletRepo;

    @Autowired
    UserDetailsService userDetailsService;


    /**
     *   这个返回好像有点错误  用的是旧版的html
     */
    @GetMapping(value = {"/", "/home"})
    public String accounts(Model model) {
        WebAuthnCredentials credential = (WebAuthnCredentials) SecurityContextHolder.getContext().getAuthentication().getCredentials();
        // 获取UserDetails对象
        WebAuthnUser user = (WebAuthnUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Wallet wallet = walletRepo.findByAppUserId(user.getId()).iterator().next();
        model.addAttribute("username", user.getUsername());
        model.addAttribute("address", wallet.getAddress());
        model.addAttribute("fidoPublicKey", Numeric.toHexString(credential.getPublicKeyCose()));
        return "home";
    }

    @GetMapping("/send")
    public String send(){
        return "send";
    }

    @GetMapping("/api/userInfo")
    @ResponseBody
    @CrossOrigin(origins = "http://localhost:30000", allowCredentials = "true")
    public CommonResult getUserInfo(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(!(authentication instanceof UsernamePasswordAuthenticationToken)){
            return CommonResult.unAuthorization();
        }
        WebAuthnCredentials credential = (WebAuthnCredentials) authentication.getCredentials();
        WebAuthnUser user = (WebAuthnUser) authentication.getPrincipal();
        Wallet wallet = walletRepo.findByAppUserId(user.getId()).iterator().next();
        Map<String, String> map = new HashMap<>();
        map.put("username", user.getUsername());
        map.put("address", wallet.getAddress());
        map.put("contractAddress", wallet.getContractAddress());
        map.put("fidoPublicKey", Numeric.toHexString(credential.getPublicKeyCose()));
        return CommonResult.success(map);
    }
}
