package com.mih.webauthn.demo.service.impl;

import com.mih.webauthn.demo.domain.L1Address;
import com.mih.webauthn.demo.domain.L1AddressRepo;
import com.mih.webauthn.demo.service.L1AddressService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class L1AddressServiceImpl implements L1AddressService {
    @Autowired
    private L1AddressRepo l1AddressRepo;

    @Override
    public void addL1Address(Long appUserId, String l1Address) {
        L1Address entity = new L1Address();
        entity.setAppUserId(appUserId);
        entity.setL1Address(l1Address);
        entity.setCreateTime(LocalDateTime.now());
        l1AddressRepo.save(entity);
    }
}
