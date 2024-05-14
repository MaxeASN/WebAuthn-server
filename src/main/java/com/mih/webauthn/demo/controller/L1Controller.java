package com.mih.webauthn.demo.controller;

import com.mih.webauthn.demo.controller.response.CommonResult;
import com.mih.webauthn.demo.domain.L1Address;
import com.mih.webauthn.demo.domain.L1AddressRepo;
import com.mih.webauthn.demo.domain.Wallet;
import com.mih.webauthn.demo.domain.WalletRepo;
import com.mih.webauthn.demo.domain.dto.L1RpcParams;
import com.mih.webauthn.demo.domain.dto.L1RpcResponse;
import com.mih.webauthn.demo.service.L1AddressService;
import com.mih.webauthn.demo.service.L1RpcService;
import com.mih.webauthn.demo.utils.UserDetailsUtils;
import io.github.webauthn.domain.WebAuthnUserRepository;
import io.github.webauthn.jpa.JpaWebAuthnUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("api/l1")
@CrossOrigin(origins = "http://localhost:30000", allowCredentials = "true")
public class L1Controller {
    @Autowired
    private L1AddressRepo l1AddressRepo;

    @Autowired
    private WebAuthnUserRepository<JpaWebAuthnUser> webAuthnUserRepository;

    @Autowired
    private L1AddressService l1AddressService;

    @Autowired
    private WalletRepo walletRepo;

    @Autowired
    private UserDetailsUtils userDetailsUtils;

    @Autowired
    @Qualifier("l1RpcService")
    private L1RpcService l1RpcService;

    @RequestMapping("list")
    public CommonResult queryL1Address(){
        // 获取登录用户的信息
        UserDetails user = userDetailsUtils.getUserDetails();
        if(user == null){
            return CommonResult.unAuthorization();
        }
        JpaWebAuthnUser userEntity = webAuthnUserRepository.findByUsername(user.getUsername()).get();
//        JpaWebAuthnUser userEntity = webAuthnUserRepository.findByUsername("chen10").get();
        List<L1Address> entityList = l1AddressRepo.findAllByAppUserId(userEntity.getId());
        List<String> l1AddressList = entityList.stream().map(L1Address -> L1Address.getL1Address().toLowerCase()).collect(Collectors.toList());
        return CommonResult.success(l1AddressList);
    }

    @RequestMapping("add")
    public CommonResult addL1Address(){
        // 获取登录用户的信息
        UserDetails user = userDetailsUtils.getUserDetails();
        if(user == null){
            return CommonResult.unAuthorization();
        }
        JpaWebAuthnUser userEntity = webAuthnUserRepository.findByUsername(user.getUsername()).get();
        Wallet wallet = walletRepo.findByAppUserId(userEntity.getId()).iterator().next();
        L1RpcResponse response = null;
        //TODO:用熔断器替代try catch
        try {
            response = l1RpcService.maxeRegistL1(L1RpcParams.registerL1Params(1, wallet.getContractAddress()));
        } catch (Exception e) {
            return CommonResult.failed("调用rpc接口生成l1 address出错");
        }
        if(response == null || response.getError() != null){
            return CommonResult.failed("调用rpc接口生成l1 address出错");
        }
        l1AddressService.addL1Address(userEntity.getId(), response.getResult().getL1Address());
        return CommonResult.success();
    }
}
