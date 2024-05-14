package com.mih.webauthn.demo.domain;

import org.springframework.data.repository.CrudRepository;

public interface WalletRepo extends CrudRepository<Wallet, Long> {
    Iterable<Wallet> findByAppUserId(Long appUserId);

    Wallet findByAddress(String address);
}
