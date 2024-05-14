package com.mih.webauthn.demo.domain;

import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface L1AddressRepo extends CrudRepository<L1Address, Long> {
    List<L1Address> findAllByAppUserId(long appUserId);

    L1Address findByL1Address(String l1Address);
}
